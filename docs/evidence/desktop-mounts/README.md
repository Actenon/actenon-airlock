# Docker Desktop mount identity

An actual local container run refused to launch because Docker Desktop reported
the writable workspace as `/host_mnt` followed by its exact host path, while
reporting the read-only control bind with the original path. All other inspected
isolation settings matched. The refusal and daemon reports are preserved in the
programme evidence.

Airlock accepts this exact prefix translation only after verifying a local Unix
Docker endpoint, a Linux engine with default seccomp, a macOS host and an engine
identified as Docker Desktop. It does not resolve arbitrary aliases, symlinks
or relative paths. Evidence retains the actual daemon-reported source. Linux
engines continue requiring exact source strings.

Negative regressions retain refusal of a different source, doubled prefix,
writable control mount, extra credential mount, wrong IPC volume, missing CPU
limit and host network. CPU quota is now independently checked alongside the
existing memory and process limits. Targeted tests: 41 passed, one documented
separate-container skip. Actual Desktop and Linux container checks are required
before merge.
