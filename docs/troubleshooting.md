# Troubleshooting

Each section starts with what you see. Airlock never sends anything anywhere to diagnose a
problem: everything below runs on your machine. `airlock doctor` checks the common causes in
one go and tells you the next step.

## Installing

### error: externally-managed-environment

You ran `pip install` with a system Python, such as Homebrew's on macOS or Debian's and
Ubuntu's. Those refuse to install packages into the system (PEP 668). Use pipx, which gives
Airlock its own environment, with the install command from the [README](../README.md#install).

### pipx: command not found

- macOS: `brew install pipx`, then `pipx ensurepath`.
- Debian and Ubuntu: `sudo apt install pipx`, then `pipx ensurepath`.
- Anything else: see [pipx's install guide](https://pipx.pypa.io/stable/installation/).

Open a new terminal afterwards. If you would rather not use pipx, the README shows the same
install in a virtual environment.

### airlock: command not found

pipx installed it, but its folder is not on your PATH yet. Run `pipx ensurepath` and open a
new terminal. `pipx list` shows where it put `airlock`.

### Failed to build ... when git checkout -q ...

The command you copied pins a branch that no longer exists. Old copies of the README did
this. Use the install command in the current [README](../README.md#install): it pins an
exact commit, which does not go away.

### requires a different Python / Python 3.11 or newer

Airlock needs Python 3.11 or newer. `python3 --version` shows what you have. With pipx you
can choose another installed Python: add `--python python3.12` to the install command.

### Cannot find command 'git'

pip and pipx need Git to fetch Airlock from GitHub.

- macOS: `xcode-select --install`.
- Debian and Ubuntu: `sudo apt install git`.

## Docker

Airlock runs the agent in a Docker container, so `airlock demo` and `airlock protect` need a
Docker engine running on this machine. Local Mode (`airlock init`, `airlock run`) does not.
When Docker is the problem, Airlock stops before it builds, approves or spends anything, and
says which of these it is.

### Docker is not installed

- macOS: install [Docker Desktop](https://docs.docker.com/desktop/setup/install/mac-install/)
  and open it once so it finishes setting up.
- Linux: install [Docker Engine](https://docs.docker.com/engine/install/).

Then run `airlock doctor`.

### Docker is not running

- macOS: `open -a Docker`, then wait until Docker Desktop says it is running.
- Linux: `sudo systemctl start docker`, or start Docker Desktop if you use it.

The same advice applies when Airlock says Docker did not answer: Docker Desktop can take a
little while to start.

### Docker permission denied

Docker is running but your user cannot use it. That is common on Linux right after
installing Docker Engine. Follow Docker's
[post-install steps](https://docs.docker.com/engine/install/linux-postinstall/), for rootless
Docker or the `docker` group. Membership of the `docker` group is equivalent to root on that
machine, so choose knowingly.

### Docker points at another machine

`DOCKER_HOST` or your Docker context points at a remote engine. Airlock only uses an engine
on this machine, because the agent's sealed copy of your project must stay here. Run
`unset DOCKER_HOST` and `docker context use default`.

### Docker is not using Linux containers

Airlock's sealed container is a Linux container. Switch Docker to Linux containers.

### Docker has no seccomp

Airlock requires Docker's seccomp system-call filter. Docker Desktop and Docker Engine enable
it by default. If you turned it off, turn it back on.

### The first run is slow

The first `airlock demo` builds a small image, and the first `airlock protect` builds the
agent's image. That downloads a base image and a few packages, once. Later runs reuse them.

## Using Airlock on a project

### airlock protect works on one project, and ... is not one

You ran `airlock protect` in your home folder or above it. Airlock refuses, so that the agent
never gets a copy of everything you own. `cd` into the project first, or pass `--path`.

### Set ANTHROPIC_API_KEY (or OPENAI_API_KEY) in this shell

`airlock protect` calls a real model, so it needs your key in the shell you run it from:
`export ANTHROPIC_API_KEY=...` for Claude Code, `export OPENAI_API_KEY=...` for Codex. Airlock
keeps the key on your machine; the agent in the container never sees it. `airlock demo` needs
no key.

### Its checks need `go` (or `tsc`, `vitest`, ...), which the image does not have

You asked for `--tests` on a Go or TypeScript project, and the agent's image has only Python
and pytest. Airlock stopped before the agent ran, so nothing was spent. Build an image with
your toolchain and dependencies and pass `--image`; see
[Your project's toolchain](real-project.md#your-projects-toolchain).

### Checks UNSUPPORTED, INCONCLUSIVE or SKIPPED

- **UNSUPPORTED**: a program the checks need is missing in the image. See the previous item.
- **INCONCLUSIVE**: no test ran, the checks timed out, or the agent changed the files that
  define your checks (for example `pyproject.toml`). Edited check configuration never counts
  as a pass unless you pass `--allow-config-change`, which is recorded.
- **SKIPPED**: tests were skipped. Skips never count as a pass unless you pass
  `--accept-skips`, which is recorded.

### The run stopped at the spend limit

Before each model call Airlock reserves the call's worst-case cost and refuses the call if
that could go over what is left of the limit. Nothing is sent for a refused call. The receipt
says what was spent (an estimate from the provider's reported usage) and that the limit
stopped the run. To allow more, run again with `--max-run-usd`, which asks you to approve the
new limit.

### Ctrl-C, a crash, or a closed terminal

The agent only ever worked on a copy, so your project is unchanged and nothing it did left
the container. Run the same command again for a fresh run. `airlock status` shows what was
recorded.

### Where are the logs and evidence?

Everything stays in your project's `.airlock/local/` folder, readable only by you:

- `logs/`: the agent's full transcript for each `airlock protect` run.
- `candidates/`: each patch the agent produced.
- `receipts.jsonl`: the signed record of every decision. `airlock receipts` verifies it.

Nothing is uploaded. Read and redact anything before you share it.

## Removing Airlock

Remove Airlock itself, then optionally its images and a project's local state:

~~~sh
pipx uninstall actenon-airlock
docker image rm actenon-airlock-compute:dev actenon-airlock-claude-code:v1 actenon-airlock-codex-cli:v1
rm -rf .airlock airlock_agent.py      # in a project where you used airlock protect
~~~

`.airlock/local/` holds that project's signing key and evidence, so delete it only when you
no longer need the record.

## Still stuck?

[Open an issue](https://github.com/Actenon/actenon-airlock/issues/new) with the output of
`airlock doctor` and the command you ran. Do not paste keys, tokens or `.airlock/local/`
files into an issue.
