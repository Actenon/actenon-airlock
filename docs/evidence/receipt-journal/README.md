# Signed receipt journal concurrency

Two broker instances previously cached different chain heads and could produce
valid individual signatures in a forked journal. All four preserved before
attacks fail: alternating writers, independent concurrent instances, spawned
processes, and an interrupted partial append.

Append now acquires a thread/process lock, reads the durable current head,
signs and writes one record, and fsyncs the file and directory before release.
Verification reads a consistent journal snapshot under a shared lock. A
partial prior append is preserved and blocks extension; it is never silently
trimmed or converted into a valid record. An OS-released lock after process
death is not permission to truncate evidence. Lock files cannot be symlinks.

New receipts also sign their key identifier in the payload; verification
requires matching signature metadata and base64url encoding. Existing signed
receipts remain verifiable with the same committed public trust anchor.
This is local POSIX journal integrity, not an external transparency anchor or
an OS sandbox. A valid prefix alone does not prove that the journal's final
records were not removed. Protected Mode must keep the keys and journal out
of the agent's writable filesystem.

The dependency graph consumes merged Protocol 1.6, Kernel #46, and Permit #27.
This does not imply that every Airlock adapter has adopted the effect ledger:
HTTP consequence observations, retry identity and operator reconciliation
remain required before the finished-product gates can pass. Cooperative local
filesystem/process releases still do not prove observed execution.
