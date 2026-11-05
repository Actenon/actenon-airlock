# Dependency upgrade breaks the type check

The development dependencies have been upgraded (`package.json` and `package-lock.json`): TypeScript 7, Vitest 5, `@types/node` 26, size-limit 14. They are installed, but the project has not been adapted, and the TypeScript project check now fails:

```
/node_modules/.bin/tsc --noEmit -p tsconfig.json
```

Adapt the project to the upgraded toolchain so that the type check, the specs and the build all pass. Keep the upgraded versions: do not edit `package.json` or `package-lock.json` (there is no network access, so nothing can be installed or downgraded). Benchmarks must still be benchmarks.

Commands (dependencies are installed at `/node_modules`):

- type check: `/node_modules/.bin/tsc --noEmit -p tsconfig.json`
- specs: `/node_modules/.bin/ts-scripts specs`
- build: `/node_modules/.bin/ts-scripts build`
