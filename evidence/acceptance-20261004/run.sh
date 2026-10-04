#!/bin/bash
# usage: run.sh <label>   (runs all acceptance commands; writes /tmp/acceptance/<label>/)
label=$1; out=/tmp/acceptance/$label; mkdir -p $out
CLEAN=(env -u GITHUB_TOKEN -u GH_TOKEN -u OPENAI_API_KEY -u ANTHROPIC_API_KEY -u DISPLAY)
step() { # name agent venv args...
  name=$1; agent=$2; venv=$3; shift 3
  cd /tmp/agents/$agent
  timeout 900 "$@" > $out/$name.stdout 2> $out/$name.stderr < ${STDIN:-/dev/null}
  echo "$name exit=$?" | tee -a $out/exits.txt
}
for a in pr-agent gpt-engineer agno; do rm -f /tmp/agents/$a/.airlock/local/receipts.jsonl; rm -rf /tmp/agents/$a/.airlock/local/replay.sqlite3; done
for a in pr-agent gpt-engineer agno; do (cd /tmp/agents/$a && "${CLEAN[@]}" /tmp/venv-$a/bin/airlock init --approve --path . > $out/$a-init.txt 2>&1; echo "$a-init exit=$?" | tee -a $out/exits.txt); done
step pr-agent-help pr-agent x "${CLEAN[@]}" /tmp/venv-pr-agent/bin/airlock run --path . -- -m pr_agent.cli --help
STDIN=/tmp/acceptance/sample.diff step pr-agent-review pr-agent x "${CLEAN[@]}" OPENAI_API_KEY=sk-airlock-acceptance-placeholder /tmp/venv-pr-agent/bin/airlock run --path . -- -m pr_agent.cli --stdin --output review.md review
step gpt-engineer-sysinfo gpt-engineer x "${CLEAN[@]}" /tmp/venv-gpt-engineer/bin/airlock run --path . -- -m gpt_engineer.applications.cli.main projects/example --sysinfo
STDIN=/tmp/acceptance/gpte-response.txt step gpt-engineer-clipboard gpt-engineer x "${CLEAN[@]}" /tmp/venv-gpt-engineer/bin/airlock run --path . -- -m gpt_engineer.applications.cli.main projects/example --llm-via-clipboard
step agno-file-tools agno x "${CLEAN[@]}" /tmp/venv-agno/bin/airlock run --path . -- cookbook/91_tools/file_tools.py
for a in pr-agent gpt-engineer agno; do
  cp /tmp/agents/$a/.airlock/local/receipts.jsonl $out/$a-receipts.jsonl 2>/dev/null
  cp /tmp/agents/$a/.airlock/public-key.json $out/$a-public-key.json
  /tmp/venv/bin/airlock receipts --path /tmp/agents/$a > $out/$a-receipts.txt 2>&1; echo "$a-receipts exit=$?" | tee -a $out/exits.txt
done
# leave the clones as found
rm -rf /tmp/agents/agno/tmp /tmp/agents/pr-agent/review.md
cd /tmp/agents/gpt-engineer && git status --short > $out/gpt-engineer-worktree.txt; git stash list >/dev/null
echo DONE >> $out/exits.txt
