# chaingate-ci: an offline CI consumer of `chaingate.check/1`

`chaingate-ci.mjs` gates a CI job on the JSON that `chaingate check --json` writes. It uses the Node
standard library only and makes no network access.

```bash
# one step produces the results: one file per expected package@version
chaingate check left-pad@1.3.0 --packument packuments/left-pad.json --json > results/left-pad.json

# the next step gates on them
node examples/ci/chaingate-ci.mjs \
  --expected expected.txt \
  --results results/ \
  --trusted-seed 974c7d7ea2f24ef627074517ea49b2f089d5e8108bc22b60401e6b1b612376dc \
  --summary chaingate-summary.json
```

`expected.txt` lists one `package@version` per line. Blank lines and `#` comments are ignored.

## Outcome

| result | outcome |
|---|---|
| every expected pair has exactly one valid result, none BLOCK | exit 0 |
| a WARN | passes, and the explanation is printed as a `::warning::` annotation |
| a BLOCK, a `refused` result or a `tool_error` | exit 1 |
| a missing, duplicate or unexpected result, an empty set, an untrusted seed, an unknown schema, a truncated file | exit 1 |
| usage error | exit 2 |

## Overrides

`decision.disposition` is always the evaluated disposition and is never rewritten. When an operator
has recorded an exact-version override with `chaingate allow`, `effective.action` is `ALLOW`, its
`basis` is `override`, and the override's reason and creation time travel with it.

By default the consumer gates on `effective.action`, so an overridden release passes. Pass
`--ignore-overrides` to gate on `decision.disposition` instead: an overridden BLOCK then fails.

## What it validates, and what it does not

It performs a specified structural validation, listed at the top of the script. It does **not** perform
full JSON Schema validation. That runs in the chaingate test suite against
`seed/v3/chaingate-check-1.schema.json`.

**Trust boundary.** The consumer trusts results produced by its own controlled CI step. The
trusted-seed check pins which seed that step used. It does not authenticate the JSON, and no signing
system is introduced.
