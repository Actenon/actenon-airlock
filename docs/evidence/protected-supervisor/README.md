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

The actual clean Linux container job subsequently passed on PR #11 at
`d13ec770ebc87ccef51655581937a554c769d050` and again at
`619338ba6548abab854a96938553f1ca93b78dec`. Run
[`37239985495`](https://github.com/Actenon/actenon-airlock/actions/runs/37239985495)
uploaded artifact `11316741859` (ZIP SHA-256
`279f594b96e38c04647fe5c66e775db83e80d9d33a488e7d4b6670cf6518ea7c`).
Its public contents are preserved in `clean-linux/`: child exit zero, original
source unchanged, thirteen bypass checks blocked, eight signed receipts verified,
five broker DENYs. Both Python versions, packaging/lint and Protected container
acceptance were green on the second exact head before consolidation.

PR #9 and #10 are preserved as merge parents in this candidate. PR #10's
stricter denial of login/startup scripts supersedes #9's allowance of a plain
login-shell command. The real sh/bash syntax attack tests from #9 remain,
alongside all #10 interpreter/wrapper, direct fork-exec and parent-symlink tests.
Parser unit tests use a deterministic PATH mapping for Linux-only utilities on
macOS; separate identity and real subprocess tests retain actual executables.
The positive wrapper test uses real GNU timeout where present, otherwise POSIX
nice. No command is marked executed by these unit-only mappings.

The required `Protected container acceptance` CI job builds a fresh credential-free
image and performs a coding fixture (model SDK, edit, pytest, shell/compile and
local git commit), then attempts thirteen alternate routes in the same container.
Five broker refusals require verified signed receipts; OS refusals are recorded
as acceptance observations, not invented per-syscall signed receipts. Public
run metadata, receipts and the public verification key are uploaded. Private
keys, bearer tokens, state databases and entire workspaces are not uploaded.

This is not an external coding-agent acceptance run, public-package installation
or G1–G40 PASS. Those remain required before the finished-product declaration.
