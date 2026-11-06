# Short help stops at an abbreviation inside the first sentence

A command's short help (the one-line summary in a group's command list) is cut at the first period, so a docstring such as `Weigh apples vs. pears.` becomes `Weigh apples vs.`. The period should end the first sentence only when it closes the text, or when the next word does not start in lowercase (`Pick a fruit. 3 remain.` still ends at `Pick a fruit.`).

When the sentence must be truncated to fit the width, truncate on word boundaries with `...` as usual: `Weigh apples vs. pears and plums.` at width 20 becomes `Weigh apples vs....`. Never split a word (including a hyphenated word) to fit; if nothing fits, return just `...`. Text shorter than the suffix is returned unchanged, and a width too narrow for the suffix, including a negative width, returns `...`.

Run the tests with `PYTHONPATH=src python3 -m pytest -q` (warnings are errors in this project).
