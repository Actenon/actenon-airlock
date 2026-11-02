# Cache drops the wrong entries under load

Two reports from production about `cachekit.TTLCache`:

1. Keys that are read constantly get evicted, while keys nobody has touched stay.
2. When entries have expired, adding a new key still pushes out a live entry, and
   `len(cache)` keeps counting entries that can no longer be read.

`python -m pytest -q` reproduces the first report. Fix the library so both reports are
resolved. Do not change the tests.
