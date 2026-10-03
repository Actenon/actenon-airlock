"""The parent owns credentials, Permit decisions, and the Kernel execution edge."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

import httpx
from actenon.gate import ActenonGate
from actenon.replay import ReplayProtector, SqliteReplayStore
from actenon_permit.boundary.proofs import Ed25519PublicKeyVerifier
from actenon_permit.ed25519_signer import load_ed25519_keypair
from actenon_permit.ledger import Ledger
from actenon_permit.model import Action, Budget, DecisionOutcome, Grant, Scopes
from actenon_permit.pdp import PDP
from actenon_permit.revocation import StoreRevocationChecker
from actenon_permit.state import SQLiteStore

from .manifest import (
    SECRET_NAME,
    AirlockError,
    authority_diff,
    capability,
    digest,
    discover,
    origin,
    request_capability,
    source_fingerprint,
    validate_url,
)
from .state import State
from .wire import LIMIT, receive, send

WELL_KNOWN = {
    "GITHUB_TOKEN": "https://api.github.com",
    "GH_TOKEN": "https://api.github.com",
    "OPENAI_API_KEY": "https://api.openai.com",
    "ANTHROPIC_API_KEY": "https://api.anthropic.com",
}
MARKER = re.compile(r"airlock_credential_[a-f0-9]{32}")


class Broker:
    def __init__(self, state: State, current: dict, bindings: dict | None = None):
        self.state = state
        self.current = current
        approved = state.approved()
        self.allowed = {capability(p) for p in approved["powers"]} & {
            capability(p) for p in current["powers"]
        }
        self.bindings = dict(WELL_KNOWN, **(bindings or {}))
        self.credentials = {}
        self.markers = {}
        for name, bound_origin in self.bindings.items():
            value = os.environ.get(name)
            if value:
                bound_origin = origin(bound_origin)
                if not bound_origin.startswith("https://"):
                    raise AirlockError("Credentials require an HTTPS origin binding")
                marker = "airlock_credential_" + uuid4().hex
                self.credentials[marker] = (value, bound_origin)
                self.markers[name] = marker
        self.saved_env = {
            name: os.environ.get(name)
            for name in ("ACTENON_SIGNING_KEY", "ACTENON_ED25519_KEY_FILE")
        }
        os.environ["ACTENON_SIGNING_KEY"] = json.loads(
            (state.local / "grant-key.json").read_text()
        )["key"]
        os.environ["ACTENON_ED25519_KEY_FILE"] = str(state.key_path)
        self.store = SQLiteStore(str(state.local / "permit.sqlite3"))
        self.pdp = PDP(self.store, Ledger(self.store))
        self.grant = Grant(
            agent_id="airlock:" + current["source_digest"],
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            scopes=Scopes(allow=sorted(self.allowed), deny=[] if self.allowed else ["*"]),
            budget=Budget(limit=1000000, remaining=1000000),
        ).sign()
        if not self.grant.verify():
            raise AirlockError("Permit grant signature failed")
        self.store.put_grant(self.grant)
        key = load_ed25519_keypair(state.key_path)
        self.edge = ActenonGate(
            verifier=Ed25519PublicKeyVerifier([key.public_key_jwk]),
            audience="service:actenon-permit-gateway",
            issuer="service:actenon-permit",
            capabilities=tuple(sorted(self.allowed)) or ("airlock.none",),
            replay_protector=ReplayProtector(SqliteReplayStore(state.local / "replay.sqlite3")),
            revocation_checker=StoreRevocationChecker(self.store),
        )
        self.http = httpx.Client(trust_env=False, follow_redirects=False)
        self.denials = 0

    def close(self):
        self.http.close()
        self.store.close()
        for name, value in self.saved_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value

    def _receipt(self, action, target, reason, **extra):
        row = {
            "schema": "actenon-airlock/receipt/v1",
            "id": "receipt_" + uuid4().hex,
            "timestamp": datetime.now(UTC).isoformat(),
            "action": action,
            "target": target,
            "source_digest": self.current["source_digest"],
            "manifest_digest": digest(self.current["powers"]),
            "authority_source": "actenon-scan/authority-evidence/v1",
            "grant_id": self.grant.id,
            "reason": reason,
            "credential_released": False,
            "execution_occurred": False,
            **extra,
        }
        self.state.receipt(row)
        return row

    def _deny(self, action, target, reason, **extra):
        self.denials += 1
        row = self._receipt(action, target, reason, decision="DENY", **extra)
        print(f"AIRLOCK DENY {action} @ {target}: {reason} [{row['id']}]", file=sys.stderr)
        return {"ok": False, "reason": reason, "receipt_id": row["id"]}

    def _headers(self, headers: dict, url: str, *, materialize: bool) -> tuple[dict, bool]:
        out, released = {}, False
        if not isinstance(headers, dict):
            raise AirlockError("Headers must be an object")
        for name, value in headers.items():
            if not isinstance(value, str):
                raise AirlockError("Header values must be strings")
            if name.lower() == "host" and value.lower() != urlsplit(url).netloc.lower():
                raise AirlockError("Host header differs from the approved URL")
            if name.lower() in {"proxy-authorization", "transfer-encoding"}:
                raise AirlockError("Transport or proxy header overrides are unsupported")
            markers = MARKER.findall(value)
            for marker in markers:
                if marker not in self.credentials:
                    raise AirlockError("Unknown credential handle")
                secret, bound = self.credentials[marker]
                if origin(url) != bound or name.lower() not in {
                    "authorization",
                    "x-api-key",
                    "api-key",
                }:
                    raise AirlockError("Credential is not bound to this header and origin")
                if materialize:
                    value = value.replace(marker, secret)
                    released = True
            out[name] = value
        return out, released

    def handle(self, message: dict) -> dict:
        if message.get("kind") == "audit-deny":
            return self._deny(
                message.get("action", "unsupported"),
                message.get("target", "<local>"),
                "Unsupported runtime effect",
            )
        action_name, target = "http.request", "<unresolved>"
        try:
            method = message["method"].upper()
            url = validate_url(message["url"])
            target = url
            if self.current["source_digest"] != source_fingerprint(self.state.root):
                raise AirlockError("Source changed after runtime discovery")
            cap, entry = request_capability(self.current, method, url, message["locations"])
            action_name = entry["action"]
            body = base64.b64decode(message.get("body", ""), validate=True)
            if (
                len(body) > LIMIT // 2
                or MARKER.search(url)
                or MARKER.search(body.decode(errors="ignore"))
            ):
                raise AirlockError("Credential handles are forbidden in URLs and request bodies")
            headers, _ = self._headers(message.get("headers", {}), url, materialize=False)
            action = Action(
                grant_id=self.grant.id,
                type=cap,
                target=url,
                params={
                    "method": method,
                    "body_sha256": hashlib.sha256(body).hexdigest(),
                    "headers_sha256": digest(headers),
                    "authority_action": action_name,
                    "authority_resource": entry["resource"],
                    "source_digest": self.current["source_digest"],
                },
                est_cost=0,
            )
            # Load the signed grant; Permit owns the actual ALLOW/DENY decision.
            grant = self.store.get_grant(self.grant.id)
            if grant is None or not grant.verify():
                raise AirlockError("Signed Permit grant could not be verified")
            decision, intent, proof = self.pdp.decide_and_mint_pccb(grant, action)
            if decision.outcome != DecisionOutcome.ALLOW:
                return self._deny(
                    action_name,
                    target,
                    decision.reason,
                    permit_decision=decision.model_dump(mode="json"),
                )
            pending = self._receipt(
                action_name,
                target,
                decision.reason,
                decision="ALLOW",
                stage="authorized",
                proof_id=proof.pccb_id,
                proof=proof.to_dict(),
                intent=intent.to_dict(),
                evidence=entry["evidence"],
            )
            response_wire = {}
            credential_released = False
            attempted = False

            def execute():
                nonlocal credential_released, attempted
                actual_headers, credential_released = self._headers(headers, url, materialize=True)
                attempted = True
                # The exact URL/body/header handles used to mint the proof are used here.
                with self.http.stream(
                    method, url, headers=actual_headers, content=body, timeout=30
                ) as response:
                    content = bytearray()
                    for part in response.iter_bytes():
                        content.extend(part)
                        if len(content) > LIMIT // 2:
                            raise AirlockError("Response exceeds 4 MiB")
                    response_headers = dict(response.headers)
                    for marker, (secret, _) in self.credentials.items():
                        content = content.replace(secret.encode(), marker.encode())
                        response_headers = {
                            k: v.replace(secret, marker) for k, v in response_headers.items()
                        }
                    response_wire.update(
                        status=response.status_code,
                        headers=response_headers,
                        body=base64.b64encode(content).decode(),
                        url=str(response.url),
                    )
                return {"http_status": response_wire["status"]}

            try:
                outcome = self.edge.protect(intent, proof, execute)
            except Exception as exc:
                row = self._receipt(
                    action_name,
                    target,
                    "Transport failed: " + type(exc).__name__,
                    decision="ALLOW",
                    stage="execution-error",
                    proof_id=proof.pccb_id,
                    credential_released=credential_released,
                    execution_attempted=attempted,
                    execution_occurred=None if attempted else False,
                    parent_receipt_id=pending["id"],
                )
                return {"ok": False, "reason": row["reason"], "receipt_id": row["id"]}
            if not outcome.ok:
                return self._deny(
                    action_name,
                    target,
                    outcome.reason_code or "Kernel refused",
                    kernel=outcome.to_dict(),
                )
            row = self._receipt(
                action_name,
                target,
                "Verified by Kernel and executed",
                decision="ALLOW",
                stage="executed",
                proof_id=proof.pccb_id,
                kernel=outcome.to_dict(),
                credential_released=credential_released,
                execution_occurred=True,
                parent_receipt_id=pending["id"],
            )
            print(f"AIRLOCK ALLOW {action_name} @ {target} [{row['id']}]", file=sys.stderr)
            return {"ok": True, "response": response_wire, "receipt_id": row["id"]}
        except Exception as exc:
            reason = (
                str(exc)
                if isinstance(exc, AirlockError)
                else "Invalid request: " + type(exc).__name__
            )
            return self._deny(action_name, target, reason)

    def child_environment(self) -> dict:
        env = {"PYTHONDONTWRITEBYTECODE": "1", "PYTHONUNBUFFERED": "1"}
        for name in ("PATH", "LANG", "LC_ALL", "LC_CTYPE", "SYSTEMROOT", "TZ"):
            if name in os.environ:
                env[name] = os.environ[name]
        from actenon_scan.authority import load_env_files

        configured, _ = load_env_files(self.state.root)
        configured.update(os.environ)
        for name in self.current["config_names"]:
            if not SECRET_NAME.search(name) and name in configured:
                env[name] = configured[name]
        env.update(self.markers)
        return env


def launch(root: Path, command: list[str], bindings: dict | None = None) -> int:
    if os.name != "posix":
        raise AirlockError("The brokered Python launcher currently requires Linux or macOS")
    current = discover(root)
    if current["parse_errors"]:
        raise AirlockError("Source parse errors block runtime launch")
    if any(not e["action"].startswith(("http.", "github.")) for e in current["blocked"]):
        raise AirlockError("Unsupported consequential effects block launch; inspect airlock diff")
    state = State(root)
    approved = state.approved()
    diff = authority_diff(approved, current)
    if diff["added"]:
        print(f"AIRLOCK: {len(diff['added'])} new powers remain blocked", file=sys.stderr)
    broker = Broker(state, current, bindings)
    parent, child = socket.socketpair()
    errors = []

    def serve():
        try:
            while True:
                send(parent, broker.handle(receive(parent)))
        except EOFError:
            pass
        except Exception as exc:
            errors.append(type(exc).__name__)
        finally:
            parent.close()

    thread = threading.Thread(target=serve, daemon=True)
    process = None
    empty_config = tempfile.TemporaryDirectory(prefix="sdk-config-", dir=state.local)
    try:
        args = [
            sys.executable,
            "-I",
            "-B",
            "-m",
            "actenon_airlock.worker",
            str(child.fileno()),
            str(root.resolve()),
            json.dumps(command),
        ]
        environment = broker.child_environment()
        environment["ANTHROPIC_CONFIG_DIR"] = empty_config.name
        environment["AIRLOCK_EMPTY_SDK_CONFIG"] = empty_config.name
        process = subprocess.Popen(args, cwd=root, env=environment, pass_fds=(child.fileno(),))
        child.close()
        thread.start()
        result = process.wait()
        thread.join(timeout=35)
        if thread.is_alive() or errors:
            raise AirlockError("Broker connection failed closed")
        return result if result else (3 if broker.denials else 0)
    finally:
        child.close()
        if process is not None and process.poll() is None:
            process.terminate()
            process.wait(timeout=10)
        broker.close()
        empty_config.cleanup()
