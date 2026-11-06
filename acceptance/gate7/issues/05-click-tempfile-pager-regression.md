# `echo_via_pager` / `get_pager_file` fail on the temporary-file pager (regression)

Since 8.4.0, paging through the temporary-file pager backend (the one used on Windows, where the pager cannot read from a pipe) fails:

```
TypeError: a bytes-like object is required, not 'str'
```

when text is written to the stream yielded by `click.get_pager_file()`, or passed to `click.echo_via_pager("hello")`. The `color` argument is also ignored on that path: ANSI styling is not stripped when `color=False` and not preserved consistently when `color=True`, unlike the pipe backend.

Expected: both entry points write the text to the pager on that backend exactly as on the pipe backend (`hello\n` reaches the pager), with `color` honoured the same way. The backend is selected on Windows, but it can be exercised on any platform by making Click think it is on Windows with a TTY and a `PAGER` such as `cat`.

Run the tests with `PYTHONPATH=src python3 -m pytest -q` (warnings are errors in this project).
