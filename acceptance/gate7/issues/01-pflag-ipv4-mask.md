# `ParseIPv4Mask` accepts IPv6 addresses; `TestParseIPv4Mask` fails

`go test ./...` fails in `ipmask_test.go`.

`ParseIPv4Mask` and `IPMask` flags are meant for IPv4 masks only. Today an IPv6 address such as `2001:db8::1` or `::` is accepted and silently turned into a mask built from its last four bytes, and setting an `IPMask` flag to an IPv6 address succeeds. These should be rejected: `ParseIPv4Mask` returns `nil` for them, and `FlagSet.Set` on an `IPMask` flag returns an error and leaves the flag's value unchanged. The existing accepted forms (`255.255.255.0`, hex `ffffff00`, and IPv4-mapped `::ffff:255.255.255.0`) must keep working.

Please find the cause and fix it so that the test suite passes. Do not change the tests.

Run the tests with `go test ./...` (the toolchain is offline; no modules need downloading).
