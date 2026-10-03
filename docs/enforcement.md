# Enforcement and trust

Scan PR #100 already supplies structured evidence. Airlock consumes its action, resource, resolution
state, HTTP URL, provenance, and source location. It does not duplicate that extractor or parse call text.
Discovery parse errors prevent runtime launch and approval.

The preserved Permit candidate has action scopes, not a native signed target-scope field.
Airlock compiles a capability as airlock.sha256(canonical(action,resource,transport)).
The compiled identifiers enter Permit's existing signed Grant.scopes.allow. No wildcard scope
is generated. Empty authority uses allow=[], deny=["*"] because legacy Permit interprets
an empty allow-list permissively. Attenuation cannot add a different compiled capability.

The runtime translator uses Scan's classify_http vocabulary, the exact transport, and a project
callsite with resolved evidence. An unresolved call translates into an identifier outside the grant,
so **Permit itself** denies it. The translator is an adapter, not a second ALLOW/DENY policy engine.
GitHub capabilities intentionally authorize an action at a repository (e.g. creating issues), not
only one item identifier. Generic URLs are exact, including scheme and query; templates are withheld.

The parent broker obtains PDP.decide_and_mint_pccb, then runs ActenonGate.protect with:

- Ed25519 signature verification rooted in the local trusted key;
- exact declared capabilities and the actual intent/target;
- request body and header-handle hashes bound as action parameters;
- durable SQLite single-use replay protection;
- StoreRevocationChecker consulting the real Permit store.

Only the verified gate callback resolves credentials and performs the HTTP request.
The actual request is captured before minting and reused in the callback. No child-selected adapter
executes in the parent. Headers cannot redirect the transport with another Host or a proxy override.
Automatic HTTP redirects and proxy environment variables are disabled. Plain credential echoes are
replaced with their handles before returning responses, but arbitrary encodings by a malicious
provider cannot be fully redacted: approved providers remain part of the trust model.

Approvals are Ed25519-signed local artifacts. The local private key is the runtime trust anchor;
replacing the tracked public key fails. CI reads the public key and baseline approval from a trusted
base Git ref rather than the PR's version. Reapproval is an explicit human operation. Possessing
the local private key permits approval; protect it with user and OS permissions.

The child launches with an environment allowlist and inherited local socket, without broker secrets.
HTTP adapters send bounded messages to the parent. Audit hooks refuse raw connections, process
spawning, filesystem mutations, and reads of known credential/local-state files. These are useful
checks for cooperative Python agents, **not a hostile-code isolation boundary**. Same-user attacks,
native extensions, in-memory monkeypatching, forged callsite messages, and a compromised interpreter
require OS isolation. There is no claim that scanning alone proves complete authority.

Source files are fingerprinted at discovery and checked before every broker operation. A source
change during the session refuses further requests. External installed dependencies remain trusted;
their code is not part of the project's source fingerprint. This cannot prevent external filesystem
races or replace immutable deployment artifacts.

Receipts record an authorization stage before dispatch and an execution stage after it.
DENY records show no credential release or execution. A failed transport after dispatch has an unknown
execution result. Kernel execution receipts are correlated with the signed proof; Airlock's local JSONL
summary is an audit log, not an independently signed cryptographic receipt.
