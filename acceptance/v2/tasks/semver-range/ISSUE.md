# Version ranges pick the wrong packages

Our resolver uses `versionlib` and two things are going wrong:

- Prerelease versions are treated as newer than the final release, and their ordering
  does not follow the Semantic Versioning 2.0.0 specification.
- Caret ranges on 0.x versions are too wide. `^0.2.3` is matching `0.9.0`, which npm and
  Cargo would never do.

`python -m pytest -q` shows a failure. Fix the library so ordering and `^` ranges follow
SemVer 2.0.0 and npm caret semantics. Do not change the tests.
