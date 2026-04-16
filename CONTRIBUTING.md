# Contributing to ChainGate

## Getting Started

```bash
git clone https://github.com/r-bedekar/chaingate.git
cd chaingate
npm install    # also activates git guard hooks via prepare script
npm test       # 243 tests, should all pass
```

Requires **Node.js 22+** (uses built-in `fetch`, `node:test`, ESM).

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

The repo includes pre-commit and commit-msg hooks (`.githooks/`) that block sensitive patterns from being committed. These activate automatically via the `prepare` script on `npm install`.

If you need to verify they're active:

```bash
git config core.hooksPath   # should print .githooks
```

## Project Structure

```
proxy/       HTTP proxy that sits between npm and the upstream registry
witness/     SQLite-backed witness store (baselines, decisions, overrides)
gates/       Deterministic gate modules (content-hash, dep-structure, etc.)
cli/         CLI commands (init, status, allow, stop, why, doctor, etc.)
collector/   Python data collector (populates the seed database, runs on VPS)
test/        Node.js test:runner tests, mirrors the source tree
```

## Pull Requests

- One logical change per PR
- Include tests for new gates or CLI commands
- Run `npm test` before pushing — all 243 tests must pass
- The pre-commit hook will catch common issues automatically

## Adding a New Gate

1. Create `gates/your-gate.js` exporting a function `(input) => { gate, result, detail }`
2. Add it to `DEFAULT_GATE_MODULES` in `gates/index.js`
3. Write tests in `test/gates/your-gate.test.js`
4. Update the gates table in README.md

## License

By contributing, you agree that your contributions will be licensed under Apache 2.0.
