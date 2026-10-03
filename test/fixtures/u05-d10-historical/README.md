# Decision histories written by the PUBLISHED runtimes (U-05 owner decision 10, C2)

Fixtures for the applicable-BLOCK rule: rows written by the published `@cgsec/chaingate` runtimes, not by this tree.
`capture.mjs` ran each published runtime's own proxy against the synthetic package `p` (seed layout 1.0, p@1.3.0 pinned
as ADV-P-130) and saved every `gate_decisions` and `overrides` row unedited, with provenance.

| file | runtime | published tarball sha256 |
|---|---|---|
| `0.1.0.json` | 0.1.0 | `fc84f4131401f31743cb4725a0050bdc65a1e6c5cae2ef98229dbebf554e3c05` |
| `0.1.1.json` | 0.1.1 (bytes downloaded from npm) | `0551df29ad5bfb8676b00111db7df814c2e998b5f07e55894562489804be4ff0` |
| `0.1.2.json` | 0.1.2 (published bytes) | `39d58a29ffd7928faafbffb577e854c4a043cc68012937b535cba045b6e20883` |

The scenarios and steps are in `capture.mjs`. Captured 2026-10-02 through qual/qrun.sh (`d10-hist-capture`).
The published legacy seed v2.1 is not on this host; the local legacy seed build has no decision rows.
