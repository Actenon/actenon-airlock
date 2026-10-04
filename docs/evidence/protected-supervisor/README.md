# Protected supervisor candidate evidence

The candidate consumes immutable Permit #33 (`6bbf731125cdde97c1f7b48697c438356a2ccca4`)
alongside the existing unified Scan, Protocol and Kernel pins.

`pin-upgrade-before.xml`: 139 passed; three old tests attempted authority mutation
through the import API now correctly rejected by Permit #32. Their updated tests
retain direct SQL corruption, which must still fail before credentials/transport.
Stale grant import is separately tested against a real reserved debit.

`unknown-method-before-fixture-update.xml`: 153 passed; one old fixture expected
an unresolved HTTP method to approve DELETE. The adapter now refuses this
widening. The fixture now requires an empty grant and no provider call. Its
initial run also documents the separate container-test skip in the host-only job.

`targeted.xml`: twenty tests passed for trusted CI review and the new protected
authority path, including exact model/body binding, observed inference,
duplicate refusal, credential withholding, self-approval/reconciliation denial,
input isolation, framing and model expansion. The model transport is explicitly
an offline fixture; all authority/proof/effect machinery is real.

The local Docker startup first timed out at bridge readiness, then at engine
availability. No agent was launched and no cooperative fallback occurred. Bounded
complete-write framing and newline-terminated JSON payloads were added. That
transport repair must pass the actual container acceptance job; unit framing
checks alone do not establish the OS boundary.

The required `Protected container acceptance` CI job builds a fresh credential-free
image and performs a coding fixture (model SDK, edit, pytest, shell/compile and
local git commit), then attempts thirteen alternate routes in the same container.
Five broker refusals require verified signed receipts; OS refusals are recorded
as acceptance observations, not invented per-syscall signed receipts. Public
run metadata, receipts and the public verification key are uploaded. Private
keys, bearer tokens, state databases and entire workspaces are not uploaded.

This is not an external coding-agent acceptance run, public-package installation
or G1–G40 PASS. Those remain required before the finished-product declaration.
