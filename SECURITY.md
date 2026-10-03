# Security policy

Do not post credentials or private advisory contents in public issues.
Use GitHub private vulnerability reporting where available, or contact the Actenon repository owners
privately to arrange disclosure. There are no published Airlock releases yet.

This development product supports cooperative Python agents at a brokered HTTP boundary.
It does not sandbox hostile Python or native code, and it does not protect against an attacker
who controls the local user account or signing key. Unsupported effects fail closed.
Read [the enforcement design](docs/enforcement.md) before relying on the runtime.
