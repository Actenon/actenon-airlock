# Release artifacts and registry readiness (release-bar item 8). Nothing published

Item 8 is "Install from public registries alone", compared with the locked artifacts. A Git-SHA
install, a local wheel or a local index **does not count**. Everything below is a dry run.

## Current state (2026-11-08)

| Package | Candidate pins (git) | Version at pin | On PyPI now | Publishable as built? |
|---|---|---|---|---|
| actenon-protocol | `a2e0e08` | 1.6.0 | up to 1.4.0 | yes (no runtime dependencies) |
| actenon-kernel | `ead6a00` | 1.3.0 | up to 1.2.1 | yes (`actenon-protocol>=1.6.0,<2`, pyyaml, cryptography) |
| actenon-permit | `85aa3ae` | **2.0.0rc1** (pre-release) | 1.4.0 | yes, as a pre-release (`actenon-kernel[asymmetric]>=1.3.0,<2`, `actenon-protocol>=1.6.0,<2`, …) |
| actenon-scan | `1638822` | 1.6.0 | up to 1.5.0 | yes (no runtime dependencies) |
| actenon-airlock | C3 (same package source as C2) / `eba7ef7` | **0.1.0.dev0** | not published | **no**: four `Requires-Dist … @ git+https://…` direct references, which PyPI rejects |

Local build hashes (wheels, at the pins, built with `python -m build`):

| Wheel | SHA-256 |
|---|---|
| `actenon_protocol-1.6.0-py3-none-any.whl` | `94db421217045658…` |
| `actenon_kernel-1.3.0-py3-none-any.whl` | `be9dc4672432e786…` |
| `actenon_permit-2.0.0rc1-py3-none-any.whl` | `4aecfd58d670df6f…` |
| `actenon_scan-1.6.0-py3-none-any.whl` | `71dc3a06470484f4…` |
| `actenon_airlock-0.1.0.dev0-py3-none-any.whl` (C2) | `34913da982b29210…` |

The full hashes, including sdists, are in `candidate-identity.json`. The builds are not yet
shown to be reproducible byte for byte: wheel timestamps would need `SOURCE_DATE_EPOCH`.

## Dry run of a coherent registry graph

1. Copy C2's tree, change `version = "0.1.0"`, and replace the four Git dependencies with
   `actenon-scan==1.6.0`, `actenon-protocol==1.6.0`, `actenon-kernel==1.3.0` and
   `actenon-permit==2.0.0rc1`.
2. Build it, and put the five Actenon wheels in a local folder.
3. Install into a fresh Python 3.12 venv, with an empty HOME and no pip cache:
   `pip install --index-url https://pypi.org/simple --find-links <folder> actenon-airlock==0.1.0`.

**Result:** the install succeeds, makes 0 Git fetches, installs exactly the five pinned Actenon
versions, and `airlock doctor --json` is `ok`. **The dependency graph is publishable.**

## What still blocks item 8

1. **A release candidate commit.**
   - It has registry metadata (as above) and a release version.
   - Its `uv.lock` is regenerated against the published files, because the admission gate's
     registry-coherence check compares PyPI file digests with `uv.lock`.
   - This is a metadata-only change to C2, with no code change. But it is a new commit, so
     **items 1–7 must be evaluated on that commit**. Decide this before the live programme, or
     every live run has to be repeated.
2. **The version decisions (owner):**
   - the Airlock release version;
   - whether Permit ships as `2.0.0rc1` or a final `2.0.0`;
   - whether the sibling PRs (Protocol #26, Kernel #51/#52, Permit #38, Scan #103) are merged
     before publishing, so the published code is on each repository's default branch.
3. **Publication:** five PyPI uploads, in dependency order: Protocol, Kernel, Permit, Scan,
   Airlock.
4. **Verification after publication:**
   - a registry-only install in a clean environment (no find-links);
   - `pip download` hashes compared with the locked artifacts;
   - the admission gate's registry-coherence check passing on the release commit.

## Provenance and supply chain (proposed; not set up)

- Publish from CI with PyPI **trusted publishing** (OIDC), not long-lived tokens, from a
  workflow pinned by commit. Attach build-provenance attestations, as `real-coding-acceptance.yml`
  already does for acceptance evidence.
- Build the wheels and sdists once, in CI, from the tagged commit. Record their SHA-256 in the
  release notes, and upload exactly those files.

## Rollback

- A bad release is **yanked** on PyPI (`pip` then stops selecting it), and a fixed version is
  published. Versions are never deleted or reused.
- Because Airlock pins its siblings with `==`, a bad sibling release cannot enter an existing
  Airlock release. Only a new Airlock release can move a pin.

## Owner actions required (none taken)

| # | Action |
|---|---|
| R1 | Decide the release version, and Permit's version |
| R2 | Approve the metadata-only release candidate commit, ideally **before** live acceptance |
| R3 | Set up trusted publishing for the five PyPI projects (account settings) |
| R4 | Approve each of the five uploads |
| R5 | Approve tagging the release commit |
