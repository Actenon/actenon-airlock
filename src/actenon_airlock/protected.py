"""Outside-process supervision using Linux containers and the existing engine.

Both containers have no network. An IPC-only bridge carries bounded data through
Docker stdio to this host supervisor; only this process owns grants, keys,
credentials and the exact HTTP execution edge. The agent never mounts the source
repository, its .airlock directory, Docker socket or host home directory.
"""

from __future__ import annotations

import base64
import json
import os
import selectors
import shutil
import stat
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path
from uuid import uuid4

from actenon_permit.model import Budget
from actenon_scan.authority import classify_http

from .broker import Broker
from .common import AirlockError, canonical, power, validate_url
from .manifest import EXCLUDED, authority_diff, capability, digest, discover, source_fingerprint
from .model_constraints import DEFAULT_ENDPOINTS, endpoint, scan_transports, validate_profile
from .state import State, atomic_json
from .wire import LIMIT

DEFAULT_IMAGE = "actenon-airlock-compute:dev"
MODEL_ENDPOINTS = {url: provider for provider, url in DEFAULT_ENDPOINTS.items()}
EXCLUDED_INPUT = EXCLUDED | {".ssh", ".aws", ".azure", ".config", ".gnupg", ".docker"}


class Docker:
    def __init__(self):
        self.binary = shutil.which("docker")
        if not self.binary:
            raise AirlockError("Protected Mode requires a running local Linux Docker engine")
        self.environment = {
            name: os.environ[name]
            for name in ("HOME", "PATH", "TMPDIR", "DOCKER_CONFIG", "DOCKER_CONTEXT", "DOCKER_HOST")
            if name in os.environ
        }
        self.host_path_prefix = None

    def call(self, args, *, timeout=45):
        try:
            result = subprocess.run(
                [self.binary, *args],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                env=self.environment,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise AirlockError("Protected Mode isolation engine unavailable") from exc
        if result.returncode:
            # No daemon diagnostic/metadata can accidentally disclose credentials.
            raise AirlockError("Protected Mode Docker operation failed: " + args[0])
        return result.stdout.strip()

    def json(self, args, *, timeout=45):
        return json.loads(self.call(args, timeout=timeout))

    def verify_engine(self, timeout=30):
        self.host_path_prefix = None
        context = self.json(["context", "inspect"], timeout=5)[0]
        endpoint = context["Endpoints"]["docker"]["Host"]
        if not self.environment.get("DOCKER_CONTEXT"):
            endpoint = self.environment.get("DOCKER_HOST") or endpoint
        if not endpoint.startswith("unix://"):
            raise AirlockError(
                "Protected Mode currently requires a local Unix-socket Docker engine"
            )
        info = self.json(["info", "--format", "{{json .}}"], timeout=timeout)
        if info.get("OSType") != "linux" or not any(
            value in {"name=seccomp,profile=builtin", "name=seccomp,profile=default"}
            for value in info.get("SecurityOptions", [])
        ):
            raise AirlockError("Protected Mode requires Linux with Docker's seccomp protection")
        # Docker Desktop's local macOS file-sharing mount is reported with this
        # prefix for some writable binds. Do not accept it on Linux or a remote
        # daemon, or normalize arbitrary paths/symlinks into reviewed mounts.
        if sys.platform == "darwin" and info.get("OperatingSystem") == "Docker Desktop":
            self.host_path_prefix = "/host_mnt"
        return {"server_version": info["ServerVersion"], "os": "linux", "seccomp": True}

    def image(self, name):
        if not name or name.startswith("-"):
            raise AirlockError("Invalid compute image")
        image = self.json(["image", "inspect", name])[0]
        if image["Config"].get("Volumes"):
            raise AirlockError("Compute images cannot declare additional writable volumes")
        return image


def availability(image=DEFAULT_IMAGE):
    try:
        docker = Docker()
        engine = docker.verify_engine(timeout=8)
        resolved = docker.image(image)
        return {"available": True, "engine": engine, "image_id": resolved["Id"]}
    except (AirlockError, ValueError, KeyError, TypeError) as exc:
        return {"available": False, "reason": str(exc)}


def snapshot(root: Path, destination: Path, secrets=()):
    """Copy regular input bytes; never carry host links, git config or credentials.

    Input repositories/images must themselves be credential-free. Known secret
    locations are excluded and the supervisor's actual bound secrets are refused
    wherever embedded. This is not a claim to discover arbitrary unknown secrets.
    """
    total = 0

    def copy(source_fd, target, depth=0):
        nonlocal total
        if depth > 64:
            raise AirlockError("Protected workspace directory depth exceeds 64")
        for child in sorted(os.scandir(source_fd), key=lambda entry: entry.name):
            if child.name in EXCLUDED_INPUT or child.name.startswith(".env"):
                continue
            metadata = child.stat(follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode) or not (
                stat.S_ISREG(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode)
            ):
                raise AirlockError("Protected workspace input contains a link or special file")
            output = target / child.name
            if stat.S_ISDIR(metadata.st_mode):
                fd = os.open(
                    child.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=source_fd
                )
                actual = os.fstat(fd)
                if (actual.st_dev, actual.st_ino) != (metadata.st_dev, metadata.st_ino):
                    os.close(fd)
                    raise AirlockError("Protected directory changed during staging")
                output.mkdir(mode=0o777)
                os.chmod(output, 0o777)
                try:
                    copy(fd, output, depth + 1)
                finally:
                    os.close(fd)
            else:
                # O_NOFOLLOW and identity checking bind the copied bytes to the inspected file.
                fd = os.open(child.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=source_fd)
                try:
                    actual = os.fstat(fd)
                    if (actual.st_dev, actual.st_ino) != (metadata.st_dev, metadata.st_ino):
                        raise AirlockError("Protected workspace input changed during staging")
                    if actual.st_size > 32 * 1024 * 1024:
                        raise AirlockError("Protected input file exceeds 32 MiB")
                    with os.fdopen(fd, "rb", closefd=False) as stream:
                        data = stream.read(32 * 1024 * 1024 + 1)
                finally:
                    os.close(fd)
                total += len(data)
                if total > 256 * 1024 * 1024:
                    raise AirlockError("Protected workspace input exceeds 256 MiB")
                if any(value and value.encode() in data for value in secrets):
                    raise AirlockError("A bound production credential occurs in workspace input")
                output.write_bytes(data)
                os.chmod(output, 0o777 if metadata.st_mode & 0o111 else 0o666)

    destination.mkdir(mode=0o777)
    os.chmod(destination, 0o777)
    source_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        copy(source_fd, destination)
    finally:
        os.close(source_fd)


class ProtectedBroker(Broker):
    """Scan vocabulary and Permit policy, with an OS-bound grant principal.

    All contained code acts as this one principal. Claimed source positions are
    not accepted as evidence. Code provenance comes from the signed manifest;
    the edge checks the actual action/resource/transport against its powers.
    """

    def __init__(self, state, current, bindings=None):
        self.approval = state.approved()
        self.approval_envelope = json.loads((state.path / "approved.json").read_text())
        if self.approval_envelope.get("payload") != self.approval:
            raise AirlockError("Approval changed during protected initialization")
        if self.approval.get("protected_model"):
            validate_profile(self.approval["protected_model"])
        self.model_transports = {**MODEL_ENDPOINTS, **scan_transports(current)}
        if self.approval.get("protected_model"):
            selected = self.approval["protected_model"]
            target = endpoint(selected)
            if (
                target in self.model_transports
                and self.model_transports[target] != selected["provider"]
            ):
                raise AirlockError("Selected model format disagrees with native Scan transport")
            self.model_transports[target] = selected["provider"]
        super().__init__(state, current, bindings)

    def grant_principal(self):
        return (
            "airlock-protected:"
            + self.current["source_digest"]
            + ":"
            + digest(self.approval_envelope)
        )

    def _receipt(self, action, target, reason, **extra):
        return super()._receipt(
            action,
            target,
            reason,
            mode="protected",
            approval_digest=digest(self.approval_envelope),
            approval=self.approval_envelope,
            provenance="signed code manifest; contained principal; no caller-position attestation",
            **extra,
        )

    def grant_budget(self):
        # A strict per-run dispatch-count limit, not a money/rolling budget claim.
        return Budget(limit=128, remaining=128, currency="calls")

    def action_cost(self, effect):
        return 1

    def bind_authority(self, effect, message):
        for candidate in effect.candidates:
            if candidate["action"] == "github.graphql":
                continue  # Consequence semantics are unresolved; no broad GraphQL grant.
            for entry in self.current["entries"]:
                if power(entry["action"], entry["resource"], entry["transport"]) == candidate:
                    return capability(candidate), dict(entry)
        first = effect.candidates[0]
        return "airlock.unresolved." + digest(first), {**first, "evidence": None}

    def model_body(self, url, body):
        provider = self.model_transports.get(url)
        if not provider:
            return body
        if provider == "unsupported":
            raise AirlockError("No protected executor for this Scan SDK operation")
        profile = self.approval.get("protected_model", {})
        if (
            profile.get("provider") != provider
            or not profile.get("models")
            or endpoint(profile) != url
        ):
            raise AirlockError("Model access requires an explicitly approved model constraint")
        request = json.loads(body)
        if not isinstance(request, dict) or request.get("model") not in profile["models"]:
            raise AirlockError("Model is outside approved authority")
        common = {"model", "messages", "temperature", "top_p", "stop", "stream", "max_tokens"}
        supported = (
            common
            | {
                "max_completion_tokens",
                "seed",
                "presence_penalty",
                "frequency_penalty",
                "n",
                "store",
            }
            if provider == "openai"
            else (common - {"stop"}) | {"system", "top_k", "stop_sequences"}
        )
        if set(request) - supported or request.get("store", False) is not False:
            raise AirlockError("Only inference without remote tools or stored state is supported")
        if request.get("n", 1) != 1:
            raise AirlockError("Multiple inference outputs are unsupported")
        bound = profile.get("max_output_tokens")
        if type(bound) is not int or not 1 <= bound <= 4096:
            raise AirlockError("Invalid approved model output bound")
        if not any(name in request for name in ("max_tokens", "max_completion_tokens")):
            request["max_tokens"] = bound
        for name in ("max_tokens", "max_completion_tokens"):
            if name in request and (
                type(request[name]) is not int or not 1 <= request[name] <= bound
            ):
                raise AirlockError("Model output exceeds the approved token bound")
        messages = request.get("messages")
        if not isinstance(messages, list) or not messages:
            raise AirlockError("Model messages are required")
        for message in messages:
            if (
                not isinstance(message, dict)
                or set(message) - {"role", "content"}
                or message.get("role") not in {"system", "user", "assistant"}
                or not isinstance(message.get("content"), str)
            ):
                raise AirlockError("Only text inference messages are supported")
        if len(canonical(request)) > 65536:
            raise AirlockError("Model input exceeds the protected 64 KiB bound")
        return canonical(request)

    def http_outcome(self, dispatch):
        if dispatch.url not in self.model_transports or dispatch.response.get("status") != 200:
            return super().http_outcome(dispatch)
        try:
            response = json.loads(base64.b64decode(dispatch.response["body"], validate=True))
            request = json.loads(dispatch.body)
            usage = response["usage"]
            if self.model_transports[dispatch.url] == "openai":
                counts = [usage["prompt_tokens"], usage["completion_tokens"]]
                output = response["choices"][0]
                valid_output = (
                    output["finish_reason"] in {"stop", "length"}
                    and output["message"]["role"] == "assistant"
                    and isinstance(output["message"]["content"], str)
                )
            else:
                counts = [usage["input_tokens"], usage["output_tokens"]]
                valid_output = response["stop_reason"] in {
                    "end_turn",
                    "max_tokens",
                    "stop_sequence",
                } and all(part["type"] == "text" for part in response["content"])
            if (
                response.get("model") == request["model"]
                and all(type(count) is int and count >= 0 for count in counts)
                and valid_output
            ):
                # This observes inference output, not downstream actions or billing settlement.
                return "COMMITTED", True
        except (ValueError, KeyError, TypeError, IndexError):
            pass
        return "AMBIGUOUS", None

    def handle(self, message):
        if message.get("kind") != "protected-http":
            return self._deny(
                "unsupported", "<protected boundary>", "No protected executor for this request"
            )
        action_name, target = "http.request", "<unresolved>"
        try:
            if (
                not isinstance(message.get("url"), str)
                or not isinstance(message.get("method"), str)
                or not isinstance(message.get("body", ""), str)
            ):
                raise AirlockError("Protected URL, method and encoded body must be strings")
            url = validate_url(message["url"])
            method = message["method"].upper()
            if method not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}:
                raise AirlockError("Unsupported HTTP method")
            action_name, target = classify_http(method, url).action, url
            body = base64.b64decode(message.get("body", ""), validate=True)
            if url in self.model_transports:
                if method != "POST":
                    raise AirlockError("Model inference requires POST")
                body = self.model_body(url, body)
            headers = message.get("headers", {})
            if not isinstance(headers, dict) or any(
                not isinstance(k, str) or not isinstance(v, str) for k, v in headers.items()
            ):
                raise AirlockError("Invalid protected headers")
            if (
                len(headers) > 64
                or sum(len(k) + len(v) for k, v in headers.items()) > 16384
                or any("\r" in k + v or "\n" in k + v for k, v in headers.items())
            ):
                raise AirlockError("Protected headers exceed transport bounds")
            # Credentials are selected by the trusted origin configuration, never agent input.
            headers = {
                k: v
                for k, v in headers.items()
                if k.lower() not in {"authorization", "x-api-key", "api-key", "host"}
            }
            for name, marker in self.markers.items():
                if self.credentials[marker][1] == self.bindings[name] and url.startswith(
                    self.bindings[name] + "/"
                ):
                    if name == "ANTHROPIC_API_KEY":
                        headers["x-api-key"] = marker
                        headers["anthropic-version"] = "2023-06-01"
                    else:
                        headers["Authorization"] = "Bearer " + marker
                    break
            return super().handle(
                {
                    "kind": "http",
                    "method": method,
                    "url": url,
                    "body": base64.b64encode(body).decode(),
                    "headers": headers,
                    "locations": [],
                }
            )
        except (AirlockError, ValueError, KeyError, TypeError) as exc:
            return self._deny(action_name, target, str(exc))


def _read_pipe(stream, size, timeout=50):
    deadline = None if timeout is None else time.monotonic() + timeout
    data = bytearray()
    with selectors.DefaultSelector() as selector:
        selector.register(stream, selectors.EVENT_READ)
        while len(data) < size:
            remaining = None if deadline is None else deadline - time.monotonic()
            if (remaining is not None and remaining <= 0) or not selector.select(remaining):
                raise AirlockError("Protected bridge timed out")
            part = os.read(stream.fileno(), size - len(data))
            if not part:
                raise EOFError("Protected bridge closed")
            data.extend(part)
    return bytes(data)


def _receive_pipe(stream, *, idle_timeout=50):
    size = struct.unpack("!I", _read_pipe(stream, 4, idle_timeout))[0]
    if size > LIMIT:
        raise AirlockError("Protected bridge message exceeds limit")
    value = json.loads(_read_pipe(stream, size))
    if not isinstance(value, dict):
        raise AirlockError("Protected bridge message must be an object")
    return value


def _write_pipe(stream, data, timeout=50):
    deadline = time.monotonic() + timeout
    os.set_blocking(stream.fileno(), False)
    pending = memoryview(data)
    with selectors.DefaultSelector() as selector:
        selector.register(stream, selectors.EVENT_WRITE)
        while pending:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not selector.select(remaining):
                raise AirlockError("Protected bridge response timed out")
            try:
                count = os.write(stream.fileno(), pending[:65536])
            except BlockingIOError:
                continue
            if not count:
                raise EOFError("Protected bridge closed")
            pending = pending[count:]


def _verify_container(docker, identity, *, agent, mounts):
    config = docker.json(["inspect", identity])[0]
    host, image = config["HostConfig"], config["Config"]
    actual_mounts = {
        row["Destination"]: {
            "rw": row["RW"],
            "type": row["Type"],
            "source": row.get("Name") if row["Type"] == "volume" else row["Source"],
        }
        for row in config["Mounts"]
    }
    matching_mounts = dict(actual_mounts)
    prefix = getattr(docker, "host_path_prefix", None)
    if prefix:
        for destination, row in actual_mounts.items():
            expected = mounts.get(destination)
            if (
                expected
                and row["type"] == expected["type"] == "bind"
                and row["source"] == prefix + expected["source"]
            ):
                matching_mounts[destination] = {**row, "source": expected["source"]}
    if not (
        host["NetworkMode"] == "none"
        and host["ReadonlyRootfs"] is True
        and not host["Privileged"]
        and host["CapDrop"] == ["ALL"]
        and not host.get("CapAdd")
        and not host.get("Devices")
        and not host.get("DeviceRequests")
        and not host.get("GroupAdd")
        and not host.get("PortBindings")
        and "no-new-privileges" in host["SecurityOpt"]
        and not any("unconfined" in option for option in host["SecurityOpt"])
        and host["PidMode"] == ""
        and host["IpcMode"] == "private"
        and host["PidsLimit"] == 128
        and host["Memory"] == 1024 * 1024 * 1024
        and host.get("NanoCpus") == 2_000_000_000
        and image["User"] == ("10000:10000" if agent else "0:0")
        and matching_mounts == mounts
    ):
        raise AirlockError(
            "Protected container isolation configuration differs from the required boundary"
        )
    return {
        "container_id": identity,
        "network": "none",
        "read_only_root": True,
        "mounts": actual_mounts,
    }


def launch_protected(root, command, *, image=DEFAULT_IMAGE):
    docker = Docker()
    engine = docker.verify_engine()  # Mandatory: no cooperative fallback.
    resolved = docker.image(image)
    current = discover(root)
    if current["parse_errors"]:
        raise AirlockError("Source parse errors block protected launch")
    state = State(root)
    approved = state.approved()
    diff = authority_diff(approved, current)
    broker = ProtectedBroker(state, current, approved.get("credential_bindings", {}))
    run_id = "protected_" + uuid4().hex
    run = state.local / "runs" / run_id
    run.mkdir(parents=True, mode=0o700)
    workspace, control = run / "workspace", run / "control"
    identities, errors, stopping = [], [], threading.Event()
    bridge = agent_process = thread = None
    volume = "airlock-ipc-" + uuid4().hex
    try:
        if any("," in str(path) for path in (workspace, control)):
            raise AirlockError("Protected workspace paths cannot contain Docker mount separators")
        snapshot(root, workspace, [secret for secret, _ in broker.credentials.values()])
        if source_fingerprint(workspace) != current["source_digest"]:
            raise AirlockError("Staged source differs from the reviewed runtime snapshot")
        control.mkdir(mode=0o755)
        for name in ("contained_bridge.py", "contained_agent.py"):
            shutil.copyfile(Path(__file__).with_name(name), control / name)
            os.chmod(control / name, 0o444)
        # Convenience routing only. The supervisor independently checks the same
        # exact target; replacing this public mapping cannot create authority.
        model_targets = {
            "/v1/chat/completions": DEFAULT_ENDPOINTS["openai"],
            "/v1/messages": DEFAULT_ENDPOINTS["anthropic"],
        }
        profile = approved.get("protected_model", {})
        if profile:
            path = "/v1/chat/completions" if profile["provider"] == "openai" else "/v1/messages"
            model_targets[path] = endpoint(profile)
        atomic_json(control / "model-targets.json", model_targets, 0o444)
        docker.call(["volume", "create", volume])
        fixed = [
            "create",
            "--pull",
            "never",
            "--network",
            "none",
            "--read-only",
            "--no-healthcheck",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--ipc",
            "private",
            "--pids-limit",
            "128",
            "--memory",
            "1g",
            "--cpus",
            "2",
            "--entrypoint",
            "python3",
        ]
        # Clear all image environment values, then supply only bounded compute configuration.
        empty_env = [
            arg
            for entry in resolved["Config"].get("Env", [])
            for arg in ("--env", entry.split("=", 1)[0] + "=")
        ]
        env = [
            "--env",
            "PATH=/usr/local/bin:/usr/bin:/bin",
            "--env",
            "HOME=/workspace/.home",
            "--env",
            "TMPDIR=/workspace/.tmp",
            "--env",
            "PYTHONDONTWRITEBYTECODE=1",
            "--env",
            "TIKTOKEN_CACHE_DIR=/opt/airlock/tiktoken",
        ]
        bridge_id = docker.call(
            [
                *fixed,
                "-i",
                "--user",
                "0:0",
                *empty_env,
                "--env",
                "PATH=/usr/local/bin:/usr/bin:/bin",
                "--mount",
                f"type=bind,source={control},target=/airlock,readonly",
                "--mount",
                f"type=volume,source={volume},target=/ipc",
                resolved["Id"],
                "-I",
                "-B",
                "/airlock/contained_bridge.py",
            ]
        )
        identities.append(bridge_id)
        boundary = _verify_container(
            docker,
            bridge_id,
            agent=False,
            mounts={
                "/airlock": {"rw": False, "type": "bind", "source": str(control)},
                "/ipc": {"rw": True, "type": "volume", "source": volume},
            },
        )
        bridge = subprocess.Popen(
            [docker.binary, "start", "-a", "-i", bridge_id],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
            env=docker.environment,
        )
        if _receive_pipe(bridge.stdout) != {"bridge": "ready", "version": 1}:
            raise AirlockError("Protected bridge readiness failed")

        def serve():
            try:
                while not stopping.is_set():
                    request = _receive_pipe(bridge.stdout, idle_timeout=None)
                    response = broker.handle(request)
                    data = json.dumps(response, separators=(",", ":")).encode()
                    if len(data) > LIMIT:
                        raise AirlockError("Protected response exceeds limit")
                    _write_pipe(bridge.stdin, struct.pack("!I", len(data)) + data)
            except (Exception,) as exc:
                if not stopping.is_set():
                    errors.append(type(exc).__name__)

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        agent_id = docker.call(
            [
                *fixed,
                "--user",
                "10000:10000",
                "--workdir",
                "/workspace",
                *empty_env,
                *env,
                "--mount",
                f"type=bind,source={control},target=/airlock,readonly",
                "--mount",
                f"type=volume,source={volume},target=/ipc,readonly",
                "--mount",
                f"type=bind,source={workspace},target=/workspace",
                resolved["Id"],
                "-I",
                "-B",
                "/airlock/contained_agent.py",
                *command,
            ]
        )
        identities.append(agent_id)
        agent_boundary = _verify_container(
            docker,
            agent_id,
            agent=True,
            mounts={
                "/airlock": {"rw": False, "type": "bind", "source": str(control)},
                "/ipc": {"rw": False, "type": "volume", "source": volume},
                "/workspace": {"rw": True, "type": "bind", "source": str(workspace)},
            },
        )
        atomic_json(
            run / "boundary.json",
            {
                "schema": "actenon-airlock/protected-run/v1",
                "run_id": run_id,
                "engine": engine,
                "image_id": resolved["Id"],
                "source_digest": current["source_digest"],
                "grant_id": broker.grant.id,
                "new_powers_blocked": len(diff["added"]),
                "bridge": boundary,
                "agent": agent_boundary,
            },
        )
        print(
            "AIRLOCK PROTECTED MODE: compute inside; external consequences cross the supervisor",
            flush=True,
        )
        agent_process = subprocess.Popen(
            [docker.binary, "start", "-a", agent_id], env=docker.environment
        )
        attach_result = agent_process.wait()
        observed_state = docker.json(["inspect", agent_id])[0]["State"]
        if (
            observed_state["Running"]
            or observed_state.get("Error")
            or attach_result not in {0, observed_state["ExitCode"]}
        ):
            raise AirlockError("Protected process completion could not be established")
        result = observed_state["ExitCode"]
        if errors:
            raise AirlockError("Protected supervisor connection failed closed")
        observation = broker._receipt(
            "process.exec",
            "contained-workspace:" + run_id,
            "Contained child exit observed; this is not a per-syscall or remote-effect attestation",
            decision="OBSERVED",
            stage="contained-compute-exited",
            execution_occurred=True,
            exit_code=result,
            image_id=resolved["Id"],
            containment=agent_boundary,
        )
        atomic_json(
            run / "result.json",
            {
                "exit_code": result,
                "denials": broker.denials,
                "execution_errors": broker.execution_errors,
                "workspace": str(workspace),
                "original_project_modified": False,
                "observation_receipt_id": observation["id"],
            },
        )
        print("Protected workspace results (untrusted files): " + str(workspace), flush=True)
        return 3 if broker.denials else (4 if broker.execution_errors else result)
    finally:
        stopping.set()
        # Remove only explicitly created containers/volume, never other local workloads.
        for identity in reversed(identities):
            try:
                docker.call(["rm", "-f", identity])
            except AirlockError:
                pass
        if bridge is not None:
            if bridge.poll() is None:
                bridge.terminate()
            try:
                bridge.wait(timeout=5)
            except subprocess.TimeoutExpired:
                bridge.kill()
                bridge.wait()
        if agent_process is not None and agent_process.poll() is None:
            agent_process.terminate()
            try:
                agent_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                agent_process.kill()
                agent_process.wait()
        if thread is not None:
            thread.join(timeout=45)
            if thread.is_alive():
                # No new requests can enter; do not close a store during an in-flight effect.
                raise AirlockError("Protected dispatch still pending; state remains held")
        try:
            docker.call(["volume", "rm", volume])
        except AirlockError:
            pass
        broker.close()
