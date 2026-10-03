# Airlock in a pull request

First approve a baseline locally and commit .airlock/approved.json and
.airlock/public-key.json on the base branch. Keep .airlock/local/ out of Git.
Then add this workflow, pinning Airlock itself to a reviewed full commit:

~~~yaml
name: Airlock Authority Review
on: [pull_request]
permissions:
  contents: read
jobs:
  authority:
    name: Airlock / Authority Review
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262
        with:
          fetch-depth: 0
          persist-credentials: false
      - uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065
        with:
          python-version: "3.12"
      - uses: Actenon/actenon-airlock@REPLACE_WITH_REVIEWED_FULL_COMMIT
        with:
          base: ${{ github.event.pull_request.base.sha }}
~~~

The action scans PR source without importing it. It writes a job summary and authority-diff.json,
and fails on new, unresolved, or unparseable authority. It requests no write token and posts no
comments. Do not use pull_request_target to execute PR code, install the PR's own dependencies,
or run the agent with production secrets in this review job.

An initial PR adding the first baseline needs a maintainer bootstrap on the trusted base; the check
will not silently accept an absent baseline. An expansion remains blocked in CI until a reviewed,
signed baseline is installed on the trusted base. Runtime reapproval and CI baseline promotion are
explicit separate operations; editing JSON in a PR cannot activate authority.
