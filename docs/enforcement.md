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
callsite with resolved evidence. Runtime bytecode positions bind source columns as well as lines.
Ambiguous await spans or callsites shared with unresolved evidence remain blocked. An unresolved
call translates into an identifier outside the grant,
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
Adapters send bounded messages to the parent. Audit hooks refuse raw connections, forks, native library
loading and ctypes symbol lookup, and reads of known credential/local-state files or of anything outside
the project and the interpreter's import paths. These are useful checks for cooperative Python agents,
**not a hostile-code isolation boundary and not an OS jail**. Same-user attacks, native extensions,
ctypes raw-memory helpers, in-memory monkeypatching, forged callsite messages, and a compromised
interpreter require OS isolation. There is no claim that scanning alone proves complete authority.
`import ctypes` is allowed because it only opens the already-loaded process image; nothing in that
handle can be called without `ctypes.dlsym`, which stays refused.

## Adapter registry

Every runtime effect goes through one pipeline, whatever its kind. Adapters are registered by
**Scan power kind**, never by agent or repository (`src/actenon_airlock/adapters.py`):

| Scan kind | Interception | Executor | Transport id |
|---|---|---|---|
| `http.*`, `github.*` (including `github.graphql`, dynamic `http.request`) | requests, httpx (sync/async), urllib | broker: the parent performs the request inside the Kernel callback | exact URL; GitHub origin |
| `process.exec` | `subprocess.Popen`, `os.system`, `os.exec*`, `os.spawn*`, `os.posix_spawn*` | agent: released after Kernel verification | `local-process` |
| `filesystem.write`, `filesystem.delete` | Scan's FILE_WRITE/DELETE tables, `pathlib.Path` methods, `open` for writing, `os.*` mutations | agent: released after Kernel verification | `local-filesystem` |
| `email.send` | `smtplib.SMTP.connect` | none: always denied with a receipt | |

1. The adapter classifies the effect into Scan's own vocabulary (`classify_http`, the program's
   basename, Scan's path normaliser). Scan stays the only source of power names.
2. The effect binds to a resolved, scanned callsite in the agent's source, using runtime bytecode
   positions. If it can't bind, it maps to an `airlock.unresolved.*` capability outside the grant.
3. Permit decides against the signed grant, the Kernel `protect()` verifies the minted proof, and
   then the executor runs. Every outcome writes a signed receipt.

Launch is refused only when Scan names a power kind that no adapter can intercept. Unresolved,
template, and unscanned calls no longer block launch; each such call is denied when reached.

A denied HTTP call raises the client library's own connection error (`requests.ConnectionError`,
`httpx.ConnectError`, `urllib.error.URLError`), which is also a `PermissionError`. Denied process and
filesystem calls raise `PermissionError`. The agent's existing error handling decides what happens
next; Airlock never kills the process for a denied call. The `airlock run` exit code is 3 when any
call was denied.

What a grant means for local effects (shown as "Scope" at approval):

- `process.exec <prog>`: run that program, resolved on the broker's PATH to the same file the agent
  would exec, with any arguments and no shell syntax. `sh -c` is accepted only for a plain command
  whose first word is the approved program. **The program itself runs outside Airlock**: whatever it
  does (for example `git clone` networking) is not mediated.
- `filesystem.write|delete <path>`: create, modify, or remove exactly that path, with Scan's
  `./`, `~/`, or absolute spelling. A Scan-named tree operation (`shutil.rmtree`, `copytree`,
  `mkdir(parents=True)`) is one effect covering its contents and needed ancestors. Writes into
  `.airlock`, `dir_fd`-relative calls, and writes that follow a symlinked leaf fail closed.
- `github.graphql`: any query or mutation the bound credential permits. Scan has no GraphQL operation
  vocabulary yet.

The scanned source files are fingerprinted at launch and checked before every broker operation.
Editing, removing, or replacing one refuses further requests. External installed dependencies remain trusted;
their code is not part of the project's source fingerprint. This cannot prevent external filesystem
races or replace immutable deployment artifacts.

Receipts record an authorization stage before dispatch and an execution stage after it.
DENY records show no credential release or execution. A failed transport after dispatch has an unknown
execution result. For agent-executed effects the final stage is `released`, with
`execution_occurred: null`: the Kernel verified the proof and the agent's process then performed the
call. Each receipt line is Ed25519-signed with the local approval key under the
`actenon-airlock/receipt/v1` domain prefix and carries the SHA-256 of the previous line.
`airlock receipts` verifies the log against the committed `.airlock/public-key.json`, so edits,
removals, and reordering are detected. Whoever holds the local private key can still rewrite the whole
log; anchor receipts externally if that matters.

## What fails closed today

- Paths, programs, URLs, and model names that come from argv, configuration, or runtime data. Scan
  cannot name them, so each such call is denied with a receipt.
- Effects inside third-party dependencies with no agent callsite that Scan names, such as litellm's
  import-time price map or a formatter's cache directory.
- With pinned Scan 1.6.0, tiktoken's encoding download and query-only URLs (`https://host?query`).
  The coordinated Scan change in `docs/scan-pr/` names both; Airlock needs no code change for it.
- aiohttp: it is not intercepted, and its raw socket connection is refused.

Source files are fingerprinted at launch. An agent that edits, removes, or replaces a scanned file
has every later effect refused. New files it creates carry no Scan evidence, so their calls are
denied, but the session continues.
