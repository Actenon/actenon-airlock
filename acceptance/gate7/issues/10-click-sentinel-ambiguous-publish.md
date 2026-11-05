# Copying or pickling a parameter breaks its `UNSET` default

Click's internal sentinels (such as `UNSET`, the default of every `Parameter` that has none) are enum members whose value is a bare `object()`. They do not survive `copy.copy`, `copy.deepcopy` or pickling: the duplicate is a new object, so code testing `value is UNSET` breaks, and in some cases constructing the duplicate fails outright.

Expected: copying, deep-copying or pickling and unpickling any sentinel returns the very same member, and duplicating a `click.Option(["--name"])` in any of these ways keeps `default is UNSET` and its name.

Run the tests with `PYTHONPATH=src python3 -m pytest -q` (warnings are errors in this project).
