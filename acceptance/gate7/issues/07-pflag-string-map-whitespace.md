# `StringToString` value loses trailing whitespace when formatted

`StringToString` flag values print their map with `String()`, for example `[key=value]`. Trailing whitespace in the last value is lost: a value of `"value "` prints as `[key=value]`, a value of only whitespace prints as `[key=]`, and a tab or non-breaking space at the end is dropped. This happens both for defaults and for values set on the command line. Values that need CSV quoting (a comma, a newline) are quoted and must stay quoted, with their trailing whitespace kept inside the quotes.

Please do the whole contributor workflow:

1. reproduce the problem with a failing test,
2. fix it,
3. add regression tests in the existing test file that fail before your fix and pass after it,
4. make sure `gofmt -l .` prints nothing and `go vet ./...` is clean,
5. run the full suite with `go test ./...`.

The toolchain is offline.
