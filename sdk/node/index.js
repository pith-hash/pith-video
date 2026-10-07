// SPDX-License-Identifier: MIT
// Copyright (c) 2026 pith-hash
"use strict";

/**
 * pith-video SDK: video fingerprinting through koffi.
 *
 * The single Rust core (the `pith-video` cdylib built by
 * `cargo build --release`) is loaded at runtime; this package's only
 * dependency is koffi, the FFI loader itself.
 *
 * Discovery order (the suite's cdylib convention):
 *
 * 1. `PITH_CDYLIB` — an explicit cdylib *file* path;
 * 2. `PITH_CDYLIB_DIR` — a *directory* scanned for the cdylib names
 *    (the CD pipeline points this at `target/release`);
 * 3. `prebuilds/<platform>-<arch>/` then `prebuilds/` (the published
 *    package ships the cdylib there);
 * 4. `<repo root>/target/release` — the repository working-tree
 *    layout, so a source checkout runs against a local cargo build
 *    with no configuration.
 *
 * The FFI surface is one fingerprint operation plus one free:
 * `pith_video_fingerprint` fingerprints a whole ISO-BMFF file
 * (mp4/mov, H.264 video track) into the canonical byte stream the
 * `reference.json` vectors are defined over, and `pith_video_free`
 * releases the handed-out buffer.
 *
 * Canonical stream layout (every multi-byte field big-endian EXCEPT
 * the MinHash words, which are little-endian because the pinned
 * `minhash_fnv1a64` / `minhash_sha256` folds hash the little-endian
 * form):
 *
 * 1. `width` u32 BE, `height` u32 BE, `sampled_frames` u32 BE;
 * 2. `duration` and `fps_sampled` as IEEE-754 bit patterns, u64 BE each;
 * 3. `sampled_frames` frame pHashes, u64 BE each, presentation order;
 * 4. exactly 128 MinHash words, u64 little-endian each;
 * 5. the raw 32-byte content digest.
 */

const koffi = require("koffi");
const fs = require("node:fs");
const path = require("node:path");

const STATUS_OK = 0;
const STATUS_INVALID = -1;
const STATUS_REJECTED = -2;

/** The MinHash signature width — part of the wire contract. */
const MINHASH_WORDS = 128;

/** Every cdylib file name cargo may drop into the build directory, per platform. */
const CDYLIB_NAMES = ["pith_video.dll", "libpith_video.so", "libpith_video.dylib"];

const PKG_ROOT = path.join(__dirname);
const REPO_ROOT = path.resolve(__dirname, "..", "..");

/** FfiError: a non-zero status code came back from the cdylib. */
class FfiError extends Error {
  /**
   * @param {string} op the FFI operation name
   * @param {number} status the raw status code
   */
  constructor(op, status) {
    const kind = { [STATUS_INVALID]: "invalid argument", [STATUS_REJECTED]: "input rejected" }[status] ?? "unknown failure";
    super(`${op} failed: ${kind} (status ${status})`);
    this.name = "FfiError";
    /** The raw status code the FFI returned. */
    this.status = status;
  }
}

/**
 * Locates the cdylib through the suite's discovery chain.
 * @returns {string} an absolute path to the cdylib file
 * @throws {Error} when nothing is found
 */
function findCdylib() {
  const explicit = process.env.PITH_CDYLIB;
  if (explicit && fs.statSync(explicit, { throwIfNoEntry: false })?.isFile()) {
    return path.resolve(explicit);
  }
  /** @type {string[]} */
  const dirs = [];
  const envDir = process.env.PITH_CDYLIB_DIR;
  if (envDir) {
    dirs.push(envDir);
    if (!path.isAbsolute(envDir)) {
      dirs.push(path.join(REPO_ROOT, envDir));
    }
  }
  const osArch = `${process.platform}-${process.arch}`;
  dirs.push(path.join(PKG_ROOT, "prebuilds", osArch));
  dirs.push(path.join(PKG_ROOT, "prebuilds"));
  dirs.push(path.join(REPO_ROOT, "target", "release"));
  for (const dir of dirs) {
    for (const name of CDYLIB_NAMES) {
      const p = path.join(dir, name);
      if (fs.statSync(p, { throwIfNoEntry: false })?.isFile()) return p;
    }
  }
  throw new Error(
    "no pith-video cdylib found (searched PITH_CDYLIB, PITH_CDYLIB_DIR, prebuilds/ and <repo>/target/release); " +
      "run `cargo build --release` first",
  );
}

let cached = undefined;

/**
 * Loads the cdylib and binds the exported symbols (lazily, once).
 * @returns {{fingerprint: Function, free: Function}}
 */
function loadLibrary() {
  if (cached) return cached;
  const lib = koffi.load(findCdylib());
  const fingerprint = lib.func("pith_video_fingerprint", "int32_t", [
    "const uint8_t *",
    "size_t",
    koffi.out(koffi.pointer("void *")),
    koffi.out(koffi.pointer("size_t")),
  ]);
  const free = lib.func("void pith_video_free(void *ptr, size_t len)");
  cached = { fingerprint, free };
  return cached;
}

/**
 * Fingerprints a complete ISO-BMFF file (mp4/mov, H.264 video track)
 * into the canonical byte stream the `reference.json` vectors are
 * defined over. The handed-out cdylib buffer is copied into a JS
 * Buffer and released before returning.
 *
 * @param {Buffer} data the complete file bytes
 * @returns {Buffer} the canonical stream (28-byte header + frame
 *   hashes + 128 LE minhash words + 32-byte digest)
 * @throws {FfiError} with `status === -2` for any refusing input
 */
function fingerprint(data) {
  if (!Buffer.isBuffer(data)) {
    throw new TypeError("data must be a Buffer");
  }
  const { fingerprint, free } = loadLibrary();
  const out = [null];
  const outLen = [0];
  const status = fingerprint(data, data.length, out, outLen);
  if (status !== STATUS_OK) {
    throw new FfiError("pith_video_fingerprint", status);
  }
  try {
    // koffi.decode hands back a Uint8Array view over the external
    // buffer; copy it into a Buffer before the cdylib buffer is freed.
    return Buffer.from(koffi.decode(out[0], "uint8_t", Number(outLen[0])));
  } finally {
    free(out[0], Number(outLen[0]));
  }
}

/**
 * Re-expresses the canonical byte stream as a plain object.
 *
 * @param {Buffer} raw the canonical stream
 * @returns {{width: number, height: number, sampledFrames: number,
 *   durationBits: string, fpsSampledBits: string, framePhashesHex: string[],
 *   minhashWord0: string, minhashWord1: string, minhashLe: Buffer,
 *   contentDigestHex: string, raw: Buffer}}
 */
function parseFingerprint(raw) {
  if (!Buffer.isBuffer(raw) || raw.length < 28 + MINHASH_WORDS * 8 + 32) {
    throw new TypeError("canonical stream is shorter than the 28-byte header, 128 minhash words and the 32-byte digest");
  }
  const sampledFrames = raw.readUInt32BE(8);
  const base = 28 + sampledFrames * 8;
  if (raw.length < base + MINHASH_WORDS * 8 + 32) {
    throw new TypeError("canonical stream is shorter than its own frame table");
  }
  const minhashLe = raw.subarray(base, base + MINHASH_WORDS * 8);
  const framePhashesHex = [];
  for (let i = 0; i < sampledFrames; i++) {
    framePhashesHex.push(raw.readBigUInt64BE(28 + i * 8).toString(16).padStart(16, "0"));
  }
  return {
    width: raw.readUInt32BE(0),
    height: raw.readUInt32BE(4),
    sampledFrames,
    durationBits: raw.readBigUInt64BE(12).toString(16).padStart(16, "0"),
    fpsSampledBits: raw.readBigUInt64BE(20).toString(16).padStart(16, "0"),
    framePhashesHex,
    minhashWord0: minhashLe.readBigUInt64LE(0).toString(16).padStart(16, "0"),
    minhashWord1: minhashLe.readBigUInt64LE(8).toString(16).padStart(16, "0"),
    minhashLe,
    contentDigestHex: raw.subarray(base + MINHASH_WORDS * 8).toString("hex"),
    raw,
  };
}

module.exports = {
  STATUS_OK,
  STATUS_INVALID,
  STATUS_REJECTED,
  MINHASH_WORDS,
  CDYLIB_NAMES,
  FfiError,
  findCdylib,
  fingerprint,
  parseFingerprint,
};
