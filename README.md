<p align="center">
  <img src="https://pith-video.n24q02m.com/logo.svg" alt="pith-video" width="120">
</p>

<h1 align="center">pith-video</h1>

<p align="center">
  <strong>Video fingerprints: mp4 demux, H.264 decode, 2 fps pHash frames and MinHash chain signature (zero-dep Rust)</strong>
</p>

<p align="center">
  <a href="https://github.com/pith-hash/pith-video/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/pith-hash/pith-video/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/pith-hash/pith-video/actions/workflows/cd.yml"><img alt="CD" src="https://github.com/pith-hash/pith-video/actions/workflows/cd.yml/badge.svg"></a>
  <a href="https://github.com/pith-hash/pith-video/releases/latest"><img alt="Latest release" src="https://img.shields.io/github/v/release/pith-hash/pith-video?display_name=tag&sort=semver"></a>
  <a href="https://github.com/n24q02m/better-semantic-release"><img alt="semantic-release" src="https://img.shields.io/badge/semantic--release-e10079?logo=semantic-release&logoColor=white"></a>
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/github/license/pith-hash/pith-video"></a>
</p>

<p align="center">
  <a href="#quick-start">Quick start</a> ·
  <a href="#the-pith-suite-contract">Suite contract</a>
</p>

<!-- BEGIN: AUTO-GENERATED-CROSS-PROMO -->
<!-- END: AUTO-GENERATED-CROSS-PROMO -->

## Overview

pith-video fingerprints a video end to end: ISO-BMFF demux (`pith-mp4`)
→ H.264 Annex-B decode (`pith-h264`) → fixed-rate 2 fps frame sampling →
per-frame 64-bit perceptual hash (`pith-image`'s pHash pipeline,
reimplemented bit-compatibly) → 128-word MinHash over consecutive
3-frame shingles (`pith-text`'s signature shape). The result is a
`VideoFingerprint`: the frame-pHash chain, its MinHash signature, the
track facts (duration, achieved fps, dimensions) and a chained tier-1
content digest over the decoded planes.

Refusals are named `Err`: fragmented MP4 (`moof`), non-AVC codecs and
unimplementable `avcC` records are `Unsupported`; malformed containers
and streams are `InvalidMagic`/`Truncated`/`BadValue`; every `Limits`
bound is `TooLarge`. Nothing panics on hostile input — 20 000
deterministic mutations and every strict prefix of a valid file are
part of the acceptance suite.

`reference.json` at the repo root pins, per fixture: the sampled
frame-pHash chain (64-bit hex), the MinHash fold, the tier-1 digest and
the `f64` facts as raw IEEE-754 bits — the cross-SDK oracle.

## Quick start

```rust
use pith_video::{Limits, decode, video_match};

let fp = decode(&mp4_bytes, &Limits::default())?;
// fp.frame_hashes.len() ≈ duration · 2 sampled frames
// fp.minhash          = 128-word MinHash over 3-frame shingles

let m = video_match(&fp, &fp2);
// m.score           = fraction of temporally aligned frames within Hamming ≤ 10
// m.minhash_jaccard = MinHash-128 Jaccard over the shingle sets
// m.matched         = m.score >= 0.8 (advisory bound)
```

Regenerate the vectors:

```bash
cargo run --locked --bin gen-reference -- gen     # rewrite reference.json
cargo run --locked --bin gen-reference -- verify  # CI's gate
```

## The pith suite contract

pith-video is part of the **pith** suite (pith-hash). Every suite repository
follows the same rules; CI enforces them mechanically:

- **Naming**: a library is always `pith-<domain>` (`pith-image`, `pith-audio`,
  `pith-zip`, ...). The curator/repository of repositories is the bare
  `pith-hash`. Never invent a second naming scheme inside the suite.
- **Version pinning**: cross-library dependencies pin `~0.1` (e.g.
  `pith-image = { version = "~0.1", path = "../pith-image" }`). The whole suite
  moves together inside 0.1.x; breaking changes require a suite-wide version
  bump, never a silent minor drift.
- **Zero third-party dependencies**: every crate depends only on other
  `pith-*` crates plus `std`. `scripts/check-zero-deps.py` (run in CI) fails
  the build on any other crate, for normal, build and dev dependencies alike.
- **No unsafe**: every crate root carries `#![forbid(unsafe_code)]`.
- **Hex-exact vectors**: `reference.json` at the repo root is the
  cross-language source of truth. The `gen-reference` binary regenerates it;
  CI verifies the committed copy is current (`gen-reference verify`), and CD
  ships the regenerated file with every SDK artifact. Python, Node and Go SDKs
  MUST test against the same bytes.

## Dependencies

Other suite crates, git-pinned on `main`: `pith-digest`, `pith-image`,
`pith-text`, `pith-mp4`, `pith-h264`. `Cargo.lock` is committed and CI
runs `--locked`.

Ported from `n24q02m/modhash` (`modhash-video`, MIT). The fixtures are
the upstream corpus byte-exact — see
[tests/fixtures/PROVENANCE.md](tests/fixtures/PROVENANCE.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) © pith-hash contributors. Portions derived from
n24q02m/modhash (MIT), Copyright (c) 2026 n24q02m.
