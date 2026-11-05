# `style()` drops color 0 and accepts invalid colors

`click.style()` (and so `click.secho()`) has two problems with `fg` and `bg`:

1. The 256-color index `0` (black) is silently ignored: `click.style("x", fg=0)` returns unstyled text instead of `"\x1b[38;5;0mx\x1b[0m"`, and the same for `bg=0`.
2. Invalid color values are not rejected consistently. Some pass through and produce garbage escape codes (for example `True`, `-1`, `256`, `(0, 0)` or a 4-tuple), the empty string is silently ignored, and unknown names raise `TypeError`.

Change the documented interface: a color is a supported color name (including the `bright_*` names and `reset`), an `int` from 0 to 255 (not a `bool`), or an RGB tuple or list of exactly three `int`s from 0 to 255 (not `bool`s). `None` means no color. **Any other value raises `ValueError`** with a message starting `Unknown color`. Update the `style()` docstring to document the new behaviour and the change from earlier versions, and add tests covering it.

Run the tests with `PYTHONPATH=src python3 -m pytest -q` (warnings are errors in this project).
