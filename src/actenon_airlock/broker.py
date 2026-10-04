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
from actenon.execution.effects import EffectProtector
from actenon.gate import ActenonGate
from actenon.replay import ReplayProtector, SqliteReplayStore
from actenon_permit.boundary.proofs import Ed25519PublicKeyVerifier
from actenon_permit.ed25519_signer import load_ed25519_keypair
from actenon_permit.kernel_bridge import claim_effect_at_edge
from actenon_permit.ledger import Ledger
from actenon_permit.model import Action, Budget, DecisionOutcome, Grant, Scopes, authority_payload
from actenon_permit.pdp import PDP
from actenon_permit.revocation import StoreRevocationChecker
from actenon_permit.state import SQLiteStore
from actenon_protocol.effects import EFFECT_PROFILE
from actenon_scan.authority import classify_http

from .adapters import CHANNELS, Context, scope
from .manifest import (
    SECRET_NAME,
    AirlockError,
    authority_diff,
    bind_runtime,
    capability,
    digest,
    discover,
    origin,
    source_files,
    source_fingerprint,
    unadapted,
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


class HttpDispatch:
    """Parent-executed HTTP: credentials materialize only inside the verified Kernel callback."""

    stage = "executed"

    def __init__(self, broker: Broker, effect, message: dict):
        self.broker, self.url, self.method = broker, effect.target, effect.params["method"]
        self.body = base64.b64decode(message.get("body", ""), validate=True)
        if (
            len(self.body) > LIMIT // 2
            or MARKER.search(self.url)
            or MARKER.search(self.body.decode(errors="ignore"))
        ):
            raise AirlockError("Credential handles are forbidden in URLs and request bodies")
        self.headers, _ = broker._headers(message.get("headers", {}), self.url, materialize=False)
        for name, value in self.headers.items():
            if name.lower() == "content-length" and value != str(len(self.body)):
                raise AirlockError("Content-Length differs from the exact approved body")
        self.params = {
            "body_sha256": hashlib.sha256(self.body).hexdigest(),
            "headers_sha256": digest(self.headers),
            "headers_effect_sha256": digest(broker._effect_headers(self.headers)),
        }
        self.consequential = not classify_http(self.method, self.url).read_only
        self.effect_reference = None
        self.response = {}
        self.credential_released = False
        self.attempted = False

    def run(self):
        broker = self.broker
        actual_headers, self.credential_released = broker._headers(
            self.headers, self.url, materialize=True
        )
        self.attempted = True
        # The exact URL/body/header handles used to mint the proof are used here.
        with broker.http.stream(
            self.method, self.url, headers=actual_headers, content=self.body, timeout=30
        ) as response:
            content = bytearray()
            for part in response.iter_bytes():
                content.extend(part)
                if len(content) > LIMIT // 2:
                    raise AirlockError("Response exceeds 4 MiB")
            response_headers = dict(response.headers)
            for marker, (secret, _) in broker.credentials.items():
                content = content.replace(secret.encode(), marker.encode())
                response_headers = {
                    k: v.replace(secret, marker) for k, v in response_headers.items()
                }
            self.response.update(
                status=response.status_code,
                headers=response_headers,
                body=base64.b64encode(content).decode(),
                url=str(response.url),
            )
        payload = {"http_status": self.response["status"]}
        if self.effect_reference is not None:
            # A transport response does not establish the remote consequence.
            # Preserve the response for the agent while keeping ownership held.
            payload["effect_evidence"] = {
                **self.effect_reference,
                "outcome": "AMBIGUOUS",
                "execution_occurred": None,
                "evidence_hash": digest(self.response),
            }
        return payload

    def reply(self) -> dict:
        return {"response": self.response}


class ReleaseDispatch:
    """Local effects need no credential: the verified Kernel callback releases the agent's call."""

    stage = "released"
    params: dict = {}
    credential_released = False

    def __init__(self, broker: Broker, effect, message: dict):
        self.attempted = False

    def run(self):
        self.attempted = True
        return {"released": True}

    def reply(self) -> dict:
        return {"response": {"released": True}}


DISPATCH = {"broker": HttpDispatch, "agent": ReleaseDispatch}


class Broker:
    def __init__(self, state: State, current: dict, bindings: dict | None = None):
        self.state = state
        self.current = current
        approved = state.approved()
        self.allowed = {capability(p) for p in approved["powers"]} & {
            capability(p) for p in current["powers"]
        }
        self.context = Context(
            root=state.root, home=Path.home(), search_path=os.environ.get("PATH", os.defpath)
        )
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
        # New files carry no Scan evidence, so only the scanned files can change authority.
        self.source_files = source_files(state.root)
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
        self.effect_namespace = "airlock-local:" + hashlib.sha256(key.public_key_bytes).hexdigest()
        self.effect_edge = ActenonGate(
            verifier=Ed25519PublicKeyVerifier([key.public_key_jwk]),
            audience="service:actenon-permit-gateway",
            issuer="service:actenon-permit",
            capabilities=tuple(sorted(self.allowed)) or ("airlock.none",),
            replay_protector=ReplayProtector(SqliteReplayStore(state.local / "replay.sqlite3")),
            revocation_checker=StoreRevocationChecker(self.store),
            effect_protector=EffectProtector(
                self.effect_namespace,
                lambda reference, request: claim_effect_at_edge(
                    reference, request, store=self.store
                ),
                lambda request: self._http_effect_descriptor(request.intent),
            ),
        )
        self.http = httpx.Client(trust_env=False, follow_redirects=False)
        self.denials = 0
        self.execution_errors = 0

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
        return self.state.receipt(row)

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

    def _effect_headers(self, headers: dict) -> dict:
        """Stable parent credential references; never raw secrets or random handles."""
        out = {}
        names = {marker: name for name, marker in self.markers.items()}
        for name, value in headers.items():
            normalized = name.lower()
            if normalized in out:
                raise AirlockError("Duplicate case-insensitive HTTP header names are unsupported")
            parts, position = [], 0
            for match in MARKER.finditer(value):
                if match.start() > position:
                    parts.append({"literal": value[position : match.start()]})
                marker = match.group()
                if marker not in names:
                    raise AirlockError("Unknown credential handle")
                parts.append({"credential": names[marker], "origin": self.credentials[marker][1]})
                position = match.end()
            if position < len(value):
                parts.append({"literal": value[position:]})
            out[normalized] = parts
        return out

    def _http_effect_descriptor(self, intent) -> dict:
        """Trusted HTTP byte identity, independent of code/proof/run metadata."""
        return {
            "profile": EFFECT_PROFILE,
            "namespace": self.effect_namespace,
            "kind": "semantic",
            "action_type": intent.action.capability,
            "target": {"type": intent.target.resource_type, "id": intent.target.resource_id},
            "semantic_key": {
                name: intent.action.parameters[name]
                for name in ("method", "body_sha256", "headers_effect_sha256")
            },
        }

    def _settle_http_effect(self, intent, proof, outcome, dispatch):
        reference = proof.extensions["effect"]
        evidence = outcome.receipt.extensions.get("effect") if outcome.receipt else None
        if evidence is None:
            if dispatch.attempted:
                # No returned receipt can turn a possible dispatch into non-execution.
                evidence = {
                    **reference,
                    "outcome": "AMBIGUOUS",
                    "execution_occurred": None,
                    "evidence_hash": digest(
                        {"proof_id": proof.pccb_id, "observation": "dispatch outcome unavailable"}
                    ),
                }
            else:
                evidence = {
                    **reference,
                    "outcome": "NOT_EXECUTED",
                    "execution_occurred": False,
                    "evidence_hash": digest(
                        {"proof_id": proof.pccb_id, "observation": "parent dispatch not entered"}
                    ),
                }
        self.store.settle_effect(
            reference=reference,
            grant_id=self.grant.id,
            principal=intent.requester.id,
            action_hash=proof.action_hash.value,
            outcome=evidence["outcome"],
            execution_occurred=evidence["execution_occurred"],
            evidence_hash=evidence["evidence_hash"],
            observer="airlock-parent-http",
        )
        return evidence

    def handle(self, message: dict) -> dict:
        if message.get("kind") == "audit-deny":
            return self._deny(
                message.get("action", "unsupported"),
                message.get("target", "<local>"),
                "Unsupported runtime effect",
            )
        adapter = CHANNELS.get(message.get("kind"))
        action_name = adapter.default_action if adapter else "unsupported"
        target, labels = "<unresolved>", {"adapter": adapter.channel if adapter else None}
        dispatch = None
        proof = None
        protected_effect = False
        try:
            if adapter is None:
                raise AirlockError("No Airlock adapter for this runtime effect")
            effect = adapter.classify(message, self.context)
            target = effect.target
            labels.update(executor=adapter.executor, detail=effect.detail)
            if self.current["source_digest"] != source_fingerprint(
                self.state.root, self.source_files
            ):
                raise AirlockError("Source changed after runtime discovery")
            cap, entry = bind_runtime(self.current, effect.candidates, message["locations"])
            action_name = entry["action"]
            if entry["evidence"] is None:
                labels["callsite"] = (message["locations"] or [None])[0]
            dispatch = (
                DISPATCH[adapter.executor](self, effect, message) if adapter.executor else None
            )
            action = Action(
                grant_id=self.grant.id,
                type=cap,
                target=target,
                params={
                    **effect.params,
                    **(dispatch.params if dispatch else {}),
                    "authority_action": action_name,
                    "authority_resource": entry["resource"],
                    "source_digest": self.current["source_digest"],
                },
                est_cost=0,
            )
            # Permit owns the immutable authority signature boundary. Compare
            # that same payload to the launch grant; live state stays in its store.
            grant = self.store.get_grant(self.grant.id)
            if (
                grant is None
                or not self.grant.verify()
                or not grant.verify()
                or authority_payload(grant.model_dump(mode="json"))
                != authority_payload(self.grant.model_dump(mode="json"))
            ):
                raise AirlockError("Signed Permit grant could not be verified")
            protected_effect = isinstance(dispatch, HttpDispatch) and dispatch.consequential
            decision, intent, proof = self.pdp.decide_and_mint_pccb(
                grant,
                action,
                **(
                    {
                        "effect_namespace": self.effect_namespace,
                        "effect_descriptor_builder": self._http_effect_descriptor,
                    }
                    if protected_effect
                    else {}
                ),
            )
            if decision.outcome != DecisionOutcome.ALLOW:
                return self._deny(
                    action_name,
                    target,
                    decision.reason,
                    permit_decision=decision.model_dump(mode="json"),
                    **(
                        {"effect_id": decision.state_delta["effect_id"]}
                        if "effect_id" in decision.state_delta
                        else {}
                    ),
                    **labels,
                )
            if dispatch is None:
                raise AirlockError("No execution adapter for " + action_name)
            if protected_effect:
                dispatch.effect_reference = proof.extensions["effect"]
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
                scope=scope(entry),
                **labels,
            )
            edge = self.effect_edge if protected_effect else self.edge
            outcome = edge.protect(intent, proof, dispatch.run)
            effect_evidence = (
                self._settle_http_effect(intent, proof, outcome, dispatch)
                if protected_effect
                else None
            )
            if protected_effect and dispatch.response:
                row = self._receipt(
                    action_name,
                    target,
                    "HTTP response received; remote consequence remains unconfirmed",
                    decision="ALLOW",
                    stage="response-received",
                    outcome=effect_evidence["outcome"],
                    effect_id=effect_evidence["effect_id"],
                    effect=effect_evidence,
                    transport_completed=True,
                    execution_occurred=effect_evidence["execution_occurred"],
                    proof_id=proof.pccb_id,
                    kernel=outcome.to_dict(),
                    credential_released=dispatch.credential_released,
                    parent_receipt_id=pending["id"],
                    evidence=entry["evidence"],
                    scope=scope(entry),
                    **labels,
                )
                print(
                    f"AIRLOCK ALLOW {action_name} @ {target}: HTTP response received; remote effect AMBIGUOUS, blind retries blocked [{row['id']}]",
                    file=sys.stderr,
                )
                return {
                    "ok": True,
                    **dispatch.reply(),
                    "receipt_id": row["id"],
                    "effect_id": effect_evidence["effect_id"],
                    "outcome": effect_evidence["outcome"],
                }
            if not outcome.ok:
                if dispatch.attempted:
                    self.execution_errors += 1
                    row = self._receipt(
                        action_name,
                        target,
                        "Execution outcome is unknown; effect remains held"
                        if effect_evidence and effect_evidence["outcome"] == "AMBIGUOUS"
                        else "Authorized dispatch failed: " + (outcome.reason_code or "unknown"),
                        decision="ALLOW",
                        stage="execution-error",
                        proof_id=proof.pccb_id,
                        kernel=outcome.to_dict(),
                        credential_released=dispatch.credential_released,
                        execution_attempted=True,
                        execution_occurred=None,
                        parent_receipt_id=pending["id"],
                        **(
                            {
                                "outcome": effect_evidence["outcome"],
                                "effect_id": effect_evidence["effect_id"],
                                "effect": effect_evidence,
                            }
                            if effect_evidence
                            else {}
                        ),
                        **labels,
                    )
                    return {"ok": False, "reason": row["reason"], "receipt_id": row["id"]}
                return self._deny(
                    action_name,
                    target,
                    outcome.reason_code or "Kernel refused",
                    kernel=outcome.to_dict(),
                    **labels,
                )
            released = dispatch.stage == "released"
            row = self._receipt(
                action_name,
                target,
                "Verified by Kernel; released to the agent process"
                if released
                else "Verified by Kernel and executed",
                decision="ALLOW",
                stage=dispatch.stage,
                proof_id=proof.pccb_id,
                kernel=outcome.to_dict(),
                credential_released=dispatch.credential_released,
                # A released local effect is performed by the agent, not observed by the broker.
                execution_occurred=None if released else True,
                parent_receipt_id=pending["id"],
                evidence=entry["evidence"],
                scope=scope(entry),
                **labels,
            )
            print(f"AIRLOCK ALLOW {action_name} @ {target} [{row['id']}]", file=sys.stderr)
            return {"ok": True, **dispatch.reply(), "receipt_id": row["id"]}
        except Exception as exc:
            if dispatch is not None and dispatch.attempted:
                # Settlement/receipt/transport failures after dispatch cannot
                # truthfully become a pre-execution DENY or release ownership.
                self.execution_errors += 1
                row = self._receipt(
                    action_name,
                    target,
                    "Execution observation unavailable; effect remains held",
                    decision="ALLOW",
                    stage="execution-error",
                    execution_occurred=None,
                    execution_attempted=True,
                    credential_released=dispatch.credential_released,
                    proof_id=proof.pccb_id if proof else None,
                    parent_receipt_id=pending["id"],
                    **(
                        {
                            "outcome": "AMBIGUOUS",
                            "effect_id": proof.extensions["effect"]["effect_id"],
                        }
                        if protected_effect and proof
                        else {}
                    ),
                    **labels,
                )
                return {"ok": False, "reason": row["reason"], "receipt_id": row["id"]}
            reason = (
                str(exc)
                if isinstance(exc, AirlockError)
                else "Invalid request: " + type(exc).__name__
            )
            return self._deny(action_name, target, reason, **labels)

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
    missing = unadapted(current)
    if missing:
        raise AirlockError(
            "No Airlock adapter can intercept these Scan powers, so launch is refused: "
            + ", ".join(missing)
        )
    state = State(root)
    approved = state.approved()
    diff = authority_diff(approved, current)
    if diff["added"]:
        print(f"AIRLOCK: {len(diff['added'])} new powers remain blocked", file=sys.stderr)
    if current["blocked"]:
        print(
            f"AIRLOCK: {len(current['blocked'])} unresolved or unadapted call sites "
            "will be denied if reached",
            file=sys.stderr,
        )
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
        return (
            result if result else (3 if broker.denials else (4 if broker.execution_errors else 0))
        )
    finally:
        child.close()
        if process is not None and process.poll() is None:
            process.terminate()
            process.wait(timeout=10)
        broker.close()
        empty_config.cleanup()
