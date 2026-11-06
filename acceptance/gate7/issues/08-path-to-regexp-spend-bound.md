# `stringify` drops the quoting of a name followed by empty text tokens

`stringify` must produce a path that parses back to the same tokens. When a parameter or wildcard name is followed by text that would continue the name (for example `bar`, or an astral character such as `𝛼`), the name is quoted: `/:"foo"bar`. That works when the text token comes directly after the name, but not when one or more **empty** text tokens sit in between, which `TokenData` built by hand can contain:

```ts
stringify(new TokenData([
  { type: "text", value: "/" },
  { type: "param", name: "foo" },
  { type: "text", value: "" },
  { type: "text", value: "" },
  { type: "text", value: "bar" },
]));
// returns "/:foobar" (a parameter named "foobar"), expected '/:"foo"bar'
```

Empty text tokens must be skipped when deciding whether to quote, for parameters and wildcards alike, so that compiling the stringified path gives the same result as compiling the original data. A following `/bar`, or nothing at all, needs no quotes.

Run the stringify specs with `/node_modules/.bin/vitest run --configLoader runner src/index.spec.ts` (dependencies are installed at `/node_modules`; the ReDoS specs in `src/redos.spec.ts` are slow on this machine and are not part of this task).
