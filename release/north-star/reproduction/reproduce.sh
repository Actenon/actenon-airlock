#!/usr/bin/env bash
# Actenon Airlock: independent reproduction harness (release-bar item 9 operator pack).
#
# One command. Free: no model calls, no accounts, no GitHub writes. It uses the network only to
# clone the public repositories, install dependencies and build images. Every result goes to
# $WORK, with a final report.json. Run it on a fresh supported machine (see OPERATOR_GUIDE.md).
#
#   bash reproduce.sh            # or: WORK=/some/dir bash reproduce.sh
#
# Exit 0 means every check matched expected.json; any mismatch exits 1 and is in report.json.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${WORK:-$PWD/airlock-reproduction-$(date -u +%Y%m%dT%H%M%SZ)}"
REPO_URL="${REPO_URL:-https://github.com/Actenon/actenon-airlock.git}"
PY="${PYTHON:-python3}"
GO_IMAGE="golang@sha256:2c4c60ef415fbfa5e90300722293bef36c5e63fae17570ce18f580af933dbd73"
mkdir -p "$WORK/results"
LOG="$WORK/reproduce.log"
exec > >(tee -a "$LOG") 2>&1

status=0
checks=()
step() { echo; echo "== $(date -u +%H:%M:%SZ) $*"; }
record() { # name, exit code, result file
  checks+=("{\"step\":\"$1\",\"exit\":$2,\"result\":\"$3\"}")
  [ "$2" -eq 0 ] || status=1
}
expect() { "$PY" -c "import json,sys; d=json.load(open('$HERE/expected.json')); print(eval('d' + sys.argv[1]))" "$1"; }

step "Environment"
{
  echo "date_utc=$(date -u +%FT%TZ)"
  echo "os=$(uname -srm)"
  echo "python=$("$PY" --version 2>&1)"
  echo "git=$(git --version)"
  echo "docker=$(docker info --format '{{.ServerVersion}} {{.OperatingSystem}} {{.Architecture}}' 2>&1)"
  echo "pack_expected_sha256=$(shasum -a 256 "$HERE/expected.json" 2>/dev/null | cut -d' ' -f1 || sha256sum "$HERE/expected.json" | cut -d' ' -f1)"
} | tee "$WORK/results/environment.txt"
"$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' || { echo "Python 3.11 or newer is required"; exit 2; }
docker info >/dev/null 2>&1 || { echo "Docker must be installed and running"; exit 2; }

CANDIDATE="$(expect "['candidate']['commit']")"
step "1. Fetch candidate $CANDIDATE"
if ! { git clone --quiet "$REPO_URL" "$WORK/airlock" && git -C "$WORK/airlock" checkout --quiet "$CANDIDATE"; }; then
  echo "Could not fetch the candidate commit. Stopping."; exit 1
fi
"$PY" "$HERE/check_results.py" identity "$WORK/airlock" > "$WORK/results/identity.json"; record identity $? results/identity.json

step "2. Build the wheel and install it (not editable) in a fresh environment"
"$PY" -m venv "$WORK/build-venv" && "$WORK/build-venv/bin/python" -m pip -q install build==1.2.2.post1
(cd "$WORK/airlock" && "$WORK/build-venv/bin/python" -m build --wheel --outdir "$WORK/dist" . > "$WORK/results/build.log" 2>&1)
WHEEL="$(ls "$WORK"/dist/actenon_airlock-*.whl 2>/dev/null | head -1)"
if [ -z "$WHEEL" ]; then
  echo "The wheel did not build; see results/build.log. Stopping: nothing after this step can be meaningful."
  record build-wheel 1 results/build.log; exit 1
fi
record build-wheel 0 results/wheel.sha256
"$PY" -m venv "$WORK/venv" && "$WORK/venv/bin/python" -m pip -q install --upgrade pip
"$WORK/venv/bin/python" -m pip -q install "$WHEEL"
# The test extras only (pyproject [test]); the product itself comes from the wheel above.
"$WORK/venv/bin/python" -m pip -q install "pytest>=8" "build>=1.2" "ruff>=0.8" "PyGithub>=2.5,<3" "openai>=1.50,<3" "anthropic>=0.40,<1"
shasum -a 256 "$WHEEL" > "$WORK/results/wheel.sha256" 2>/dev/null || sha256sum "$WHEEL" > "$WORK/results/wheel.sha256"
SITE="$("$WORK/venv/bin/python" -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')"
"$PY" "$HERE/check_results.py" installed "$SITE" > "$WORK/results/installed.json"; record installed-dependencies $? results/installed.json
"$WORK/venv/bin/airlock" doctor --json > "$WORK/results/doctor.json"; record doctor $? results/doctor.json

step "3. Build the images from the candidate's Dockerfiles (IDs are recorded; builds are not bit-reproducible)"
cd "$WORK/airlock"
for spec in "containers/Dockerfile.compute actenon-airlock-compute:dev ." \
            "containers/Dockerfile.claude-code actenon-airlock-claude-code:v1 ." \
            "containers/Dockerfile.codex-cli actenon-airlock-codex-cli:v1 ." \
            "examples/toolchains/Dockerfile.go airlock-example-go:ci examples/toolchains/sample-go" \
            "examples/toolchains/Dockerfile.node airlock-example-node:ci examples/toolchains/sample-node"; do
  set -- $spec
  docker build -q -f "$1" -t "$2" "$3" >/dev/null && echo "$2 $(docker image inspect -f '{{.Id}}' "$2")" | tee -a "$WORK/results/images.txt"
done

step "4. Integration suite (as the CI integration job runs it)"
env -u AIRLOCK_TEST_PROTECTED_IMAGE "$WORK/venv/bin/python" -m pytest -q -p no:cacheprovider --junitxml="$WORK/results/test-results.xml" > "$WORK/results/integration.log" 2>&1
tail -1 "$WORK/results/integration.log"
"$PY" "$HERE/check_results.py" junit "$WORK/airlock" integration-python-3.12 "$WORK/results/test-results.xml" > "$WORK/results/junit-integration.json"; record junit-integration $? results/junit-integration.json

step "5. Container suites (as the CI container job runs them)"
FILES="$(grep -o 'python -m pytest -q tests/test_protected.py[^-]*' .github/workflows/ci.yml | sed 's/python -m pytest -q //')"
AIRLOCK_TEST_GO_IMAGE=airlock-example-go:ci AIRLOCK_TEST_NODE_IMAGE=airlock-example-node:ci \
AIRLOCK_TEST_PROTECTED_IMAGE=actenon-airlock-compute:dev AIRLOCK_TEST_CODEX_IMAGE=actenon-airlock-codex-cli:v1 \
AIRLOCK_CODEX_EVIDENCE="$WORK/results/codex-evidence" AIRLOCK_TEST_CLAUDE_CODE_IMAGE=actenon-airlock-claude-code:v1 \
AIRLOCK_PROTECTED_EVIDENCE="$WORK/results/protected-evidence" \
  "$WORK/venv/bin/python" -m pytest -q -p no:cacheprovider $FILES --junitxml="$WORK/results/protected-results.xml" > "$WORK/results/protected.log" 2>&1
tail -1 "$WORK/results/protected.log"
AIRLOCK_TEST_PROTECTED_IMAGE=actenon-airlock-compute:dev AIRLOCK_INDEPENDENT_EVIDENCE="$WORK/results/independent-evidence" \
  "$WORK/venv/bin/python" -m pytest -q -p no:cacheprovider tests/test_independent_container.py --junitxml="$WORK/results/independent-boundary-results.xml" > "$WORK/results/independent.log" 2>&1
tail -1 "$WORK/results/independent.log"
"$PY" "$HERE/check_results.py" junit "$WORK/airlock" protected-container-acceptance "$WORK/results/protected-results.xml" "$WORK/results/independent-boundary-results.xml" > "$WORK/results/junit-container.json"; record junit-container $? results/junit-container.json

step "6. Independent offline verifier (Go standard library; no Airlock code)"
want="$(expect "['independent_verifier']['source_sha256']")"
got="$(shasum -a 256 "$HERE/../verifier/airlock_verify.go" 2>/dev/null | cut -d' ' -f1 || sha256sum "$HERE/../verifier/airlock_verify.go" | cut -d' ' -f1)"
[ "$want" = "$got" ] || { echo "verifier source differs from expected.json"; status=1; }
mkdir -p "$WORK/verifier"
docker run --rm --network none -e HOME=/tmp -e GOCACHE=/tmp/c -e GOTOOLCHAIN=local -v "$HERE/../verifier:/v:ro" -v "$WORK/verifier:/out" -w /v "$GO_IMAGE" \
  go build -trimpath -o /out/airlock_verify airlock_verify.go
git ls-files 'release/**/receipts.jsonl' 'docs/evidence/**/receipts.jsonl' > "$WORK/results/journals.txt"
docker run --rm --network none -v "$WORK/airlock:/repo:ro" -v "$WORK/verifier:/b:ro" -v "$WORK/results:/r" -w /repo "$GO_IMAGE" sh -c \
  'while read j; do d=$(dirname "$j"); cp=""; [ -f "$d/checkpoint.json" ] && cp="-checkpoint $d/checkpoint.json"; o=$(/b/airlock_verify -journal "$j" -public-key "$d/public-key.json" $cp); printf "%s EXIT=%s\n" "$(printf "%s" "$o" | tr -d "\n")" "$?"; done < /r/journals.txt' > "$WORK/results/independent-verifier.txt"
"$PY" "$HERE/check_results.py" journals "$WORK/results/independent-verifier.txt" > "$WORK/results/journals.json"; record journals $? results/journals.json

step "6b. Tamper self-test: the verifier must reject an edited, a truncated and a reordered journal"
T="$WORK/tamper"; mkdir -p "$T"; G="release/gate5-rerun-gate6/live/gate6"
cp "$G/public-key.json" "$G/checkpoint.json" "$T/"
sed -n '1,14p' "$G/receipts.jsonl" > "$T/truncated.jsonl"
(sed -n '1,2p' "$G/receipts.jsonl"; sed -n '4p' "$G/receipts.jsonl"; sed -n '3p' "$G/receipts.jsonl"; sed -n '5,$p' "$G/receipts.jsonl") > "$T/reordered.jsonl"
sed '5s/"decision":"[A-Z]*"/"decision":"ALLOW"/; 5s/"action":"/"action":"x/' "$G/receipts.jsonl" > "$T/edited.jsonl"
rejected=0
for f in truncated reordered edited; do
  docker run --rm --network none -v "$T:/t:ro" -v "$WORK/verifier:/b:ro" "$GO_IMAGE" /b/airlock_verify -journal /t/$f.jsonl -public-key /t/public-key.json -checkpoint /t/checkpoint.json >/dev/null 2>&1 && echo "NOT rejected: $f" || { echo "rejected: $f"; rejected=$((rejected+1)); }
done
[ "$rejected" -eq 3 ]; record tamper-self-test $? "tamper: $rejected of 3 rejected"

step "7. Provider observations (offline consistency of the published Gate 6 records)"
"$PY" "$HERE/check_results.py" provider "$WORK/airlock" > "$WORK/results/provider.json"; record provider $? results/provider.json

step "Report"
printf '{"schema":"actenon-airlock/reproduction-report/v1","candidate":"%s","work":"%s","overall_ok":%s,"checks":[%s]}\n' \
  "$CANDIDATE" "$WORK" "$([ $status -eq 0 ] && echo true || echo false)" "$(IFS=,; echo "${checks[*]}")" | "$PY" -m json.tool > "$WORK/report.json"
cat "$WORK/report.json"
echo; echo "Send OPERATOR_RECORD.md (filled in) and $WORK/report.json, $WORK/results/. Nothing in them is secret."
exit $status
