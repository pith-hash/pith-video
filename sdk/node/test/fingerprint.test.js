// SPDX-License-Identifier: MIT
// Copyright (c) 2026 pith-hash
"use strict";

// Hex-exact conformance: the committed reference vectors through koffi.
// Every vector in the repository-root reference.json is replayed through
// the cdylib. The 9 pinned vectors compare every pinned field hex-exact —
// frame pHash chain, MinHash fold (word 0/1, FNV-1a 64 and SHA-256 over
// the little-endian word bytes) and the content digest. The 2
// stability-excluded solid-color vectors (short_32x24.mp4, tiny_16x16.mp4)
// compare only the platform-independent fields — their pHash bits and the
// MinHash fold over them sit at the DCT subnormal noise floor and are
// libm-sensitive, so they are never compared cross-platform. Every
// recorded decode error kind comes back as an FfiError, never a crash.

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const { FfiError, findCdylib, fingerprint, parseFingerprint } = require("../index.js");

const REPO_ROOT = path.resolve(__dirname, "..", "..", "..");
const REFERENCE = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "reference.json"), "utf8"));

/** The standard FNV-1a 64 the minhash fold is pinned with. */
function fnv1a64(data) {
  let h = 0xcbf29ce484222325n;
  for (const b of data) {
    h ^= BigInt(b);
    h = (h * 0x100000001b3n) & 0xffffffffffffffffn;
  }
  return h;
}

test("cdylib is discoverable", () => {
  assert.ok(fs.statSync(findCdylib()).isFile());
});

for (const vector of REFERENCE.vectors) {
  test(`reference vector ${vector.name} is reproduced`, () => {
    const data = fs.readFileSync(path.join(REPO_ROOT, vector.input_path));

    const raw = fingerprint(data);
    const fp = parseFingerprint(raw);
    // Platform-independent facts, pinned for every vector.
    assert.equal(fp.width, vector.width, vector.name);
    assert.equal(fp.height, vector.height, vector.name);
    assert.equal(fp.sampledFrames, vector.sampled_frames, vector.name);
    assert.equal(fp.durationBits, vector.duration_bits, vector.name);
    assert.equal(fp.fpsSampledBits, vector.fps_sampled_bits, vector.name);
    assert.equal(fp.contentDigestHex, vector.content_digest_sha256, vector.name);

    if (!vector.phash_hex_pinned) {
      // Stability-excluded solid-color source: the pHash bits and the
      // MinHash fold over them sit at the DCT subnormal noise floor
      // (libm-sensitive); only the fields above are a cross-platform
      // contract.
      return;
    }

    assert.deepEqual([...fp.framePhashesHex], vector.frame_phashes_hex, vector.name);
    assert.equal(fp.minhashWord0, vector.minhash_word_0, vector.name);
    assert.equal(fp.minhashWord1, vector.minhash_word_1, vector.name);
    // The folds hash the LITTLE-ENDIAN word bytes — recomputed here
    // with the standard algorithms, not trusted from the cdylib.
    assert.equal(fnv1a64(fp.minhashLe).toString(16).padStart(16, "0"), vector.minhash_fnv1a64, vector.name);
    assert.equal(crypto.createHash("sha256").update(fp.minhashLe).digest("hex"), vector.minhash_sha256, vector.name);
  });
}

for (const error of REFERENCE.errors) {
  test(`decode error ${error.name} is refused, not crashing`, () => {
    const data =
      error.input_kind === "inline-hex"
        ? Buffer.from(error.input_hex, "hex")
        : fs.readFileSync(path.join(REPO_ROOT, error.input_path));
    assert.throws(() => fingerprint(data), (err) => {
      assert.ok(err instanceof FfiError);
      if (data.length > 0) {
        // Non-empty refusals reach the decoder and come back rejected.
        assert.equal(err.status, -2);
      }
      // A zero-length buffer may surface as either refusal depending
      // on whether the binding hands the cdylib a null pointer; the
      // contract is a status code, never a crash.
      return true;
    });
  });
}

test("full stream matches a rust-pinned value", () => {
  // a_64x48.mp4's facts, pinned in the committed reference.json and
  // re-derived by the Rust unit tests; this test fails loudly even if
  // reference.json were regenerated wrongly.
  const data = fs.readFileSync(path.join(REPO_ROOT, "tests", "fixtures", "a_64x48.mp4"));
  const raw = fingerprint(data);
  const fp = parseFingerprint(raw);
  assert.equal(fp.durationBits, "4010000000000000");
  assert.equal(fp.fpsSampledBits, "4000000000000000");
  assert.equal(fp.framePhashesHex[0], "ac798c7786266e8c");
  assert.equal(fp.minhashWord0, "2a9354939727ac5d");
  assert.equal(fp.contentDigestHex, "72a4bbfd76647b2dc9ee06d8d6975ae73ff1ba2e789877dbc3ca88e37fc718aa");
  assert.deepEqual([...raw.subarray(0, 12)], [0, 0, 0, 64, 0, 0, 0, 48, 0, 0, 0, 8]);
});
