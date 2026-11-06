# Warn when a parameter name collides, and keep the help option clear of user parameters

Two problems with parameter names:

1. An argument and another parameter that share a name silently overwrite each other's value during parsing. For example `@click.option("--target")` together with `@click.argument("target")`: whichever is processed last wins, with no warning. Options may deliberately share a name (feature switches), so that stays allowed, but whenever an **argument** shares its name with any other parameter, Click should emit a `UserWarning` whose message contains `'target' is used by an argument` (with the actual name quoted), telling the user to give each parameter a unique name.

2. A command with an argument named `help` (`@click.argument("help")`) breaks the automatic `--help` option, because the help option stores its value under the name `help` too. The automatic help option should store its value under a reserved internal name, `_click_default_help`, so `--help` and a parameter called `help` both keep working. If a user parameter does claim that reserved name, emit a `UserWarning` whose message contains `reserved for the automatic help option`. `Parameter.to_info_dict()` for the help option then reports that reserved name.

Update the help-option paragraph in `docs/documentation.md` to describe the new behaviour.

Existing behaviour must be preserved otherwise: options competing for one name, help option names taken over by user options, and help output are unchanged.

Run the tests with `PYTHONPATH=src python3 -m pytest -q` (warnings are errors in this project).
