# Honour `IsBoolFlag()` on custom flag values

The standard library's `flag` package treats any `Value` with an `IsBoolFlag() bool` method returning true as a boolean flag. pflag only does this for its own `bool` type, so custom boolean-like values behave inconsistently:

- `--tristate` or `-t` with no value fails with "flag needs an argument", unless the caller remembered to set `NoOptDefVal = "true"` by hand. Adding such a flag should set `NoOptDefVal` to `"true"` automatically when it is empty.
- In usage output, a custom value whose `IsBoolFlag()` is true should print like a boolean: no type name, and no "(default ...)" suffix when its default is `false` or empty. For a custom type named `custom-bool` registered with `fs.Var(&v, "custom-bool", "custom bool value implementation")`, `PrintDefaults` should print exactly `      --custom-bool[=true]   custom bool value implementation` followed by a newline.
- A flag whose default is empty counts as a zero-valued default for such values.

The behaviour of the built-in `bool` flags, and of values that implement `IsBoolFlag()` returning false, must not change. The fix spans the boolean-value code and the shared flag and usage code.

Run the tests with `go test ./...` (the toolchain is offline).
