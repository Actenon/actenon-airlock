# Rate limiter starves callers that poll frequently

Our API gateway polls `TokenBucket.consume()` every few tens of milliseconds. With
`fill_rate=10` we expect about ten requests per second to get through, but once the
bucket has drained almost nothing is admitted. Slow callers are fine.

`python -m pytest -q` shows the failure. Please find the cause and fix the library.
Do not change the tests.
