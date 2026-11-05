# Gate 6: what the owner provides and authorises

**Nothing here is authorised yet.** Running the live programme makes:

- one billable Claude Code run with `claude-opus-5-5`, with an estimated maximum of **$2** and no retries
- **at most one real file creation** in one disposable GitHub repository

The procedure and success criteria are in `GATE6_LIVE_PROTOCOL.md`. The synthetic rehearsal of exactly this programme is `rehearsal/gate6-b48db96/`, explained in `GATE6_DEMO.md`.

## 1. Inputs (all owner-held; never pasted into chat)

| # | Input | How | Where it goes |
|---|---|---|---|
| 1 | Disposable repository | `gh repo create <you>/airlock-gate6-disposable --private --add-readme`. Then turn off Actions for it (Settings → Actions → Disable actions). No bots, apps, collaborators or other sessions may write to it during the run | — |
| 2 | Target branch | The default branch, e.g. `main` | `facts.json` |
| 3 | Expected parent commit | The branch head at the moment you collect the facts (see the command below). Do not push anything after collecting it | `facts.json` |
| 4 | Destination file | Fixed: `airlock-gate6/token-bucket-fix.patch`. It must not exist yet | built into the frozen runner |
| 5 | Write token | Fine-grained PAT: *only this repository*, **Contents: Read and write** (Metadata: Read is automatic), 7-day expiry | owner-only file, e.g. `~/.gate6-write` |
| 6 | Read-only token (a different token) | Fine-grained PAT: *only this repository*, **Contents: Read-only**, 7-day expiry. The runner refuses it if it equals the write token | owner-only file, e.g. `~/.gate6-read` |
| 7 | Anthropic API key | A **fresh** Console key. Revoke the one used for Gate 5 | owner-only file, e.g. `~/.actenon-anthropic-key` |
| 8 | Frozen candidate | `gate6-freeze-<sha>.json`, written by Claude from the reviewed PR head and given to you with its SHA-256 | `~/src/actenon-audit/live-gate6/` |
| 9 | External spend limit | A monthly spend limit on the Anthropic Console workspace that owns the key, e.g. $5. It is enforced by Anthropic, outside Airlock | Console |
| 10 | Authorisation | The statement in §3, in chat, and the same repository, branch and path on the command line | chat and `--authorize-github-write` |

Save each secret with a hidden prompt, so it never appears on screen, in the clipboard or in shell history. Run this once per file, changing the file name:

```bash
(umask 077; read -rs "k?Paste the token, then press Return: "; print -r -- "$k" > ~/.gate6-write); echo
```

Collect the repository facts yourself (replace the three values):

```bash
O=<owner>; R=airlock-gate6-disposable; B=main; P=$(gh api repos/$O/$R/branches/$B --jq .commit.sha); gh api repos/$O/$R --jq "{repo_id: .id, repo_node_id: .node_id, owner: .owner.login, repo: .name, branch: \"$B\", expected_parent_sha: \"$P\"}" > ~/src/actenon-audit/live-gate6/facts.json; cat ~/src/actenon-audit/live-gate6/facts.json
```

## 2. What happens, and where it can stop

1. **Local checks.** Nothing leaves the machine yet. Every credential file must be owner-only and a single line, the two GitHub tokens must differ, `facts.json` must have exactly six fields, and the authorisation string must match the facts exactly.
2. **Freeze drift check.** The code, image, packages, model and prices must equal the freeze byte for byte.
3. **Read-only pre-check, using the read token.** The repository ID and node ID must match, the branch head must equal the parent, and the target file must be absent.
4. **Anthropic pre-flight.** One promptless model lookup.
5. **The agent runs.** One Claude Code run in Protected Mode; Airlock captures and tests the patch.
6. **The owner review pause.** The exact write and patch are printed. **You type the first 12 characters of the content SHA-256**, or anything else to stop with nothing written.
7. **Six refusal controls,** each of which must be refused before anything reaches GitHub (`GATE6_DEMO.md` §3). If any is not, the run stops and the approved write is **never attempted**.
8. **One write.** The approved create is sent once. Its outcome is not taken from the reply.
9. **Replay refused.** An identical replay is refused.
10. **Two readbacks.** Airlock's own readback settles the effect. The referee then checks the bytes, parent and changed files again, with the read-only token.

Every stop before step 8 leaves GitHub unchanged. A failure or AMBIGUOUS outcome after step 8 is **not retried and not fixed by hand**. Report it, and reconcile only with `airlock reconcile <effect> --github-readback`.

## 3. The authorisation statement

Fill in the brackets from your `facts.json` and the freeze you were given, then send it in chat:

> I authorise one live Gate 6 run, and only one, from freeze `gate6-freeze-<sha>.json` (SHA-256 `<freeze sha256>`) at commit `<sha>`.
>
> It may spend up to $2 estimated on `claude-opus-5-5` inference, with no retries and no model change.
>
> It may make one GitHub file creation:
> - repository `<owner>/<repo>` (ID `<repo_id>`, node ID `<repo_node_id>`)
> - branch `<branch>`, on parent `<expected_parent_sha>`
> - path `airlock-gate6/token-bucket-fix.patch`
> - content limited to the patch I approve at the prompt by its hash prefix
>
> I will keep every other writer away from this repository until the run and both readbacks finish.

The same repository, branch and path are passed on the command line:

```bash
unset ANTHROPIC_API_KEY GITHUB_TOKEN; cd ~/src/actenon-audit/airlock-gate6 && .venv/bin/python acceptance/github-consequence/run.py live --out ~/src/actenon-audit/live-gate6/run --config ~/src/actenon-audit/live-gate6/gate6-freeze-<sha>.json --authorized-usd 2 --anthropic-credential-file ~/.actenon-anthropic-key --github-credential-file ~/.gate6-write --readback-credential-file ~/.gate6-read --repo-facts ~/src/actenon-audit/live-gate6/facts.json --authorize-github-write '<owner>/<repo>@<branch>:airlock-gate6/token-bucket-fix.patch'
```

Copy the `KEY-PIN gate6 …` line it prints into a note outside the evidence folder.

## 4. Afterwards

1. Open the commit on github.com yourself.
2. Revoke both GitHub tokens.
3. Send the full terminal output to Claude for verification and evidence packaging.

The Gate 6 owner record is written only on your explicit approval after that review.
