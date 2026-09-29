# Contributing to ChainGate

## Getting Started

```bash
git clone https://github.com/r-bedekar/chaingate.git
cd chaingate
npm install
npm run hooks  # activates the git guard hooks (.githooks/)
npm test       # the full suite; every test should pass
```

Requires **Node.js 22 or 24** (the majors that are tested; see the README).

## Development

Start the proxy locally:

```bash
node proxy/server.js
# chaingate-proxy listening on http://127.0.0.1:6173
```

Run tests:

```bash
npm test                                    # full suite
npm run test:witness                        # witness store tests only
node --test test/gates/content-hash.test.js # single file
```

## Guard Hooks

The repo includes pre-commit and commit-msg hooks (`.githooks/`) that block sensitive patterns from being committed. Activate them once per clone with `npm run hooks`. (There is deliberately no `prepare` script: npm treats it as an install script of the published package and warns every user who installs it.)

If you need to verify they're active:

```bash
git config core.hooksPath   # should print .githooks
```

## Project Structure

```
proxy/       HTTP proxy that sits between npm and the upstream registry
witness/     SQLite-backed witness store (baselines, decisions, overrides)
gates/       gate modules (content-hash, dep-structure, and others)
patterns/    detection patterns (publisher identity, provenance)
seed/        v3 seed reader, evaluator and conformance tools
cli/         CLI commands (init, status, check, why, allow, stop, doctor, and others)
examples/    the offline CI consumer
validation/  validation scripts, methodology and reports
test/        node:test tests, laid out like the source tree
```

## Pull Requests

- One logical change per PR
- Include tests for new gates or CLI commands
- Run `npm test` before pushing; every test must pass
- The pre-commit hook will catch common issues automatically

## Adding a New Gate

1. Create `gates/your-gate.js` exporting a function `(input) => { gate, result, detail }`
2. Add it to `DEFAULT_GATE_MODULES` in `gates/index.js`
3. Write tests in `test/gates/your-gate.test.js`
4. Update the gates table in README.md

## License

By contributing, you agree that your contributions will be licensed under Apache 2.0.
