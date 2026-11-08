# Getting started

This takes about ten minutes, most of it the one-time image build. Steps 1 to 4 are free and
need no account or key. Step 5 calls a real model and costs a few cents, and only after you
approve.

## 1. Check what you have

~~~sh
python3 --version     # 3.11 or newer
git --version
docker info --format '{{.ServerVersion}}'    # prints a version when Docker is running
pipx --version
~~~

Missing something? Python: [python.org](https://www.python.org/downloads/) or `brew install
python`. Git on macOS: `xcode-select --install`. Docker: [Docker Desktop](https://docs.docker.com/desktop/)
on macOS, [Docker Engine](https://docs.docker.com/engine/install/) on Linux. pipx: `brew install
pipx` or `sudo apt install pipx`, then `pipx ensurepath` and open a new terminal.

## 2. Install Airlock

~~~sh
pipx install "git+https://github.com/Actenon/actenon-airlock.git@eba7ef796b706643726710bf6b7309726e0fbda5"
~~~

That is one exact commit of the development candidate. It brings the other Actenon components
it needs; you do not install them yourself.

## 3. Ask Airlock whether it is ready

~~~sh
airlock doctor
~~~

It ends with **Ready** and what to do next, or **Not ready** and the one thing to fix. For
example, if Docker is not running it tells you how to start it. Nothing is sent anywhere.

## 4. Watch it stop an attack, for free

~~~sh
airlock demo
~~~

The first time, it builds a small image (a few minutes). Then it runs a script that fixes a
bug and then tries to steal fake secrets: once in an ordinary container, where it succeeds,
and once in Airlock's Protected Mode, where nothing gets out. In the second part the fix is
tested, approved as one exact change, sent once to Airlock's local stand-in for GitHub,
refused when replayed, and confirmed by reading it back. Every line comes from what was
observed, and the demo says so plainly if anything did not happen as described.

## 5. Let a real agent fix a real bug

Make a practice project with one failing test, and keep a copy of the test outside it:

~~~sh
mkdir -p ~/airlock-practice && cd ~/airlock-practice
printf 'def add(a, b):\n    return a - b\n' > calculator.py
printf 'from calculator import add\n\n\ndef test_add():\n    assert add(2, 3) == 5\n' > test_calculator.py
mkdir -p ~/airlock-practice-tests && cp test_calculator.py ~/airlock-practice-tests/
~~~

Put your model key in this shell. Airlock keeps it on your machine; the agent never sees it.

~~~sh
export ANTHROPIC_API_KEY=...      # Claude Code; or OPENAI_API_KEY for Codex CLI
airlock protect --tests ~/airlock-practice-tests "Fix the failing test"
~~~

What happens:

1. The first run builds the agent's image (a few minutes, once).
2. Airlock shows what you are approving: which model, at what prices, up to which spend limit
   per run ($2.00 by default), and anything it found in the project but will not grant. It
   also shows the checks it will run afterwards. Answer `y` to approve, or anything else to
   stop with nothing spent.
3. The agent works in the sealed container. You see short lines such as `reading`,
   `editing calculator.py` and `running pytest`. Its own summary is labelled as its claim.
4. Your test checks the change in a separate sealed container.
5. The receipt says what changed, whether the check passed, what was refused, about what it
   cost and what is uncertain. It ends with the command to apply the patch.

Your project has not changed yet. The receipt ends with the exact command to take the
patch, which looks like this; read the patch first, then run the command if you want it:

~~~sh
git apply .airlock/local/candidates/<id>/candidate.patch
python3 -m pytest -q
~~~

`git apply` works whether or not the folder is a Git repository. Running the same command again approves
nothing new: the signed approval is reused until you change the model, the limit or the prices.

## 6. On your own project

`cd` into it and run `airlock protect` with your task. Keep the tests you trust outside the
project and pass them with `--tests`, so the agent cannot change what counts as passing. Go
and TypeScript projects need an image with their toolchain; Airlock checks before anything
runs and prints the command. See [real projects](real-project.md).

## Clean up

~~~sh
rm -rf ~/airlock-practice ~/airlock-practice-tests
pipx uninstall actenon-airlock
~~~

The images can be removed too; see [troubleshooting](troubleshooting.md#removing-airlock).
