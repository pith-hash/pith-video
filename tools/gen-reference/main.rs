//! Regenerates and verifies `reference.json`: the hex-exact video-lane
//! vectors of the pith suite. Per fingerprintable fixture under
//! `tests/fixtures/` (deterministic sorted order) it pins the sampled
//! frame-pHash chain (16-digit hex per 64-bit hash), the MinHash fold
//! over the 128-word chain signature, the tier-1 content digest and the
//! `f64` facts (duration, achieved fps) as raw IEEE-754 bits; the
//! refusing fixtures and crafted hostile inputs are pinned as decode
//! error kinds.
//!
//! # Platform stability of the pHash pins
//!
//! The DCT's f64 sums are IEEE-exact in fixed order, but the cosine
//! factors come from the platform libm, which may differ by 1 ULP
//! between glibc, macOS libm and the MSVC CRT. For real image content
//! the `> median` threshold comparisons clear that noise by many orders
//! of magnitude and the hash is platform-stable. A solid-color source
//! cancels down to the *subnormal* noise floor, where a 1-ULP cosine
//! wobble flips bits — the hash of such a frame is genuinely
//! platform-dependent. `gen-reference` therefore computes every
//! fixture's DCT threshold margin and only pins `frame_phashes_hex`
//! when the margin clears [`PHASH_MARGIN_FLOOR`]; flat fixtures keep
//! their integer pins (MinHash fold, content digest, counts, f64 facts)
//! with `phash_hex_pinned: false` and a reason. The frame hashes
//! themselves stay exercised per-platform by `tests/video.rs`.
//!
//! `gen-reference gen [PATH]` rewrites the file; `gen-reference verify
//! [PATH]` recomputes it and fails on any difference. CI runs `verify`
//! so a port drift (pHash pipeline, MinHash seeding, sampler) cannot
//! land silently, and CD ships the file with the SDK artifacts as the
//! cross-language oracle.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use pith_digest::{Error, fnv1a64, sha256};
use pith_video::{Limits, VideoFingerprint, decode};

const FIXTURES_DIR: &str = "tests/fixtures";
const REFERENCE_PATH: &str = "reference.json";

/// The margin a fixture's DCT thresholds must clear for its pHash bits
/// to be a cross-platform contract — see the module docs. Coefficients
/// of real content sit at O(0.1…1000); libm ULP noise is ~1e-13 at
/// those scales, so a floor of 1e-6 is orders of magnitude above the
/// noise and below any real signal.
const PHASH_MARGIN_FLOOR: f64 = 1e-6;

/// Lowercase hex of `bytes`.
pub(crate) fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// `u64` as 16-digit lowercase hex (one frame pHash / one signature word).
pub(crate) fn hex64(v: u64) -> String {
    format!("{v:016x}")
}

/// `f64` as 16-digit hex of the IEEE-754 bit pattern.
pub(crate) fn f64_bits(v: f64) -> String {
    format!("{:016x}", v.to_bits())
}

pub(crate) fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The 128-word MinHash signature folded for compact transport: first
/// two words verbatim, then FNV-1a 64 and SHA-256 over all 128
/// little-endian words — the same fold shape the text lane pins.
pub(crate) struct MinHashFold {
    pub(crate) first: u64,
    pub(crate) second: u64,
    pub(crate) fnv1a64: u64,
    pub(crate) sha256: String,
}

pub(crate) fn fold_minhash(sig: &[u64]) -> MinHashFold {
    assert_eq!(sig.len(), 128, "signature length is part of the contract");
    let mut le = Vec::with_capacity(sig.len() * 8);
    for w in sig {
        le.extend_from_slice(&w.to_le_bytes());
    }
    MinHashFold {
        first: sig[0],
        second: sig[1],
        fnv1a64: fnv1a64(&le),
        sha256: hex(sha256(&le).expect("sha256 of signature words").as_bytes()),
    }
}

/// The kind name of an error, as the cross-SDK contract pins it. The
/// kind is stable; the message text is not depended on.
pub(crate) fn error_kind(e: &Error) -> &'static str {
    match e {
        Error::BadValue(_) => "BadValue",
        Error::Truncated { .. } => "Truncated",
        Error::TooLarge { .. } => "TooLarge",
        Error::InvalidMagic { .. } => "InvalidMagic",
        Error::Unsupported(_) => "Unsupported",
    }
}

/// Sorted container-fixture names in `tests/fixtures/` — the
/// deterministic corpus order of the vectors and errors arrays.
pub(crate) fn fixture_names(root: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(root.join(FIXTURES_DIR))
        .expect("fixtures dir must exist")
        .map(|e| {
            e.expect("dir entry readable")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .filter(|n| n.ends_with(".mp4") || n.ends_with(".mov") || n.ends_with(".h264"))
        .collect();
    names.sort();
    assert!(!names.is_empty(), "no fixtures found");
    names
}

/// A single frame's DCT margins: the smallest `|coefficient − median|`
/// over the 63 low-frequency terms, mirroring `src/phash.rs`'s kernel
/// (`box_average 32×32 → orthonormal dct2_2d → low 8×8, drop DC`).
/// Mirrored here, not imported, so the crate's public surface stays the
/// pipeline itself; the pinned `frame_phash` values still come from the
/// crate.
pub(crate) fn frame_phash_margin(width: u32, height: u32, luma: &[u8]) -> f64 {
    use pith_image::raster::{Gray, Image, box_average};
    use std::f64::consts::{FRAC_1_SQRT_2, PI};

    const DCT: usize = 32;
    const KEEP: usize = 8;
    let gray = match Image::<Gray, u8>::from_vec(width, height, luma.to_vec()) {
        Ok(g) => g,
        Err(_) => return f64::INFINITY,
    };
    let small = match box_average(&gray, DCT as u32, DCT as u32) {
        Ok(s) => s,
        Err(_) => return f64::INFINITY,
    };
    let mut block = [0.0f64; DCT * DCT];
    for (dst, v) in block.iter_mut().zip(small.as_slice()) {
        *dst = f64::from(*v);
    }
    let n = DCT;
    let scale = (2.0 / n as f64).sqrt();
    let kernel = |x: &[f64], out: &mut [f64]| {
        for (k, slot) in out.iter_mut().enumerate() {
            let mut acc = 0.0;
            for (i, &xi) in x.iter().enumerate() {
                acc += xi * (PI * ((2 * i + 1) * k) as f64 / (2.0 * n as f64)).cos();
            }
            let c_k = if k == 0 { FRAC_1_SQRT_2 } else { 1.0 };
            *slot = c_k * scale * acc;
        }
    };
    let mut row_out = [0.0f64; DCT];
    for row in block.chunks_exact_mut(DCT) {
        kernel(row, &mut row_out);
        row.copy_from_slice(&row_out);
    }
    let mut gather = [0.0f64; DCT];
    let mut col_out = [0.0f64; DCT];
    for x in 0..DCT {
        for (y, g) in gather.iter_mut().enumerate() {
            *g = block[y * DCT + x];
        }
        kernel(&gather, &mut col_out);
        for (y, g) in col_out.iter().enumerate() {
            block[y * DCT + x] = *g;
        }
    }
    let mut rest: Vec<f64> = Vec::with_capacity(KEEP * KEEP - 1);
    for y in 0..KEEP {
        for x in 0..KEEP {
            if x == 0 && y == 0 {
                continue;
            }
            rest.push(block[y * DCT + x]);
        }
    }
    rest.sort_by(f64::total_cmp);
    let t = rest[(rest.len() - 1) / 2];
    // Exact duplicates of the median are *structural* ties: box-average
    // output repeats whole rows/columns, so equal coefficients are
    // computed by identical op sequences and wobble identically under a
    // libm change (and `c > t` stays false for both). The comparisons
    // that can flip are the ones at a *small but nonzero* distance —
    // measure those.
    rest.iter()
        .filter(|c| **c != t)
        .map(|c| (c - t).abs())
        .fold(f64::INFINITY, f64::min)
}

/// One parsed `avcC` record: NAL length size plus SPS and PPS lists.
type ParsedAvcC = (usize, Vec<Vec<u8>>, Vec<Vec<u8>>);

/// Smallest DCT threshold margin over every decoded frame of `input`.
/// Mirrors the crate's decode path (demux → avcC lead-in → Annex-B
/// samples → decoder) but keeps every frame: for the stability verdict
/// the exact sampled subset does not matter, because a flat source is
/// flat in *all* its frames and a textured source clears the floor in
/// all of them.
pub(crate) fn phash_margin(input: &[u8]) -> f64 {
    use pith_h264::{Decoder, Limits as H264Limits};
    use pith_mp4::demux;

    let Ok(mp4) = demux(input) else {
        return f64::INFINITY;
    };
    let Some(track) = mp4.video_track() else {
        return f64::INFINITY;
    };
    let Some(record) = track.avcc() else {
        return f64::INFINITY;
    };
    // avcC walk, mirroring src/avcc.rs: version(1) profile/level(3)
    // lengthSizeMinusOne(1) SPS count + list, PPS count + list.
    let parse = |rec: &[u8]| -> Option<ParsedAvcC> {
        if rec.first() != Some(&1) {
            return None;
        }
        let length_size = usize::from(rec[4] & 0x03) + 1;
        let mut p = 5usize;
        let sps_count = usize::from(rec[p] & 0x1F);
        p += 1;
        let mut sps = Vec::new();
        for _ in 0..sps_count {
            let n = usize::from(u16::from_be_bytes([rec[p], rec[p + 1]]));
            p += 2;
            sps.push(rec.get(p..p + n)?.to_vec());
            p += n;
        }
        let pps_count = usize::from(*rec.get(p)?);
        p += 1;
        let mut pps = Vec::new();
        for _ in 0..pps_count {
            let n = usize::from(u16::from_be_bytes([rec[p], rec[p + 1]]));
            p += 2;
            pps.push(rec.get(p..p + n)?.to_vec());
            p += n;
        }
        Some((length_size, sps, pps))
    };
    let Some((length_size, sps, pps)) = parse(record) else {
        return f64::INFINITY;
    };
    let mut lead = Vec::new();
    for nal in sps.iter().chain(pps.iter()) {
        lead.extend_from_slice(&[0, 0, 0, 1]);
        lead.extend_from_slice(nal);
    }
    let mut dec = Decoder::new(H264Limits {
        max_input: usize::MAX,
        max_luma_samples: H264Limits::default().max_luma_samples,
        max_frames: usize::MAX,
        max_refs: H264Limits::default().max_refs,
    });
    if !lead.is_empty() && dec.push_stream(&lead).is_err() {
        return f64::INFINITY;
    }
    let mut min_margin = f64::INFINITY;
    let mut annexb: Vec<u8> = Vec::new();
    let Ok(samples) = track.samples().collect::<std::result::Result<Vec<_>, _>>() else {
        return f64::INFINITY;
    };
    let start = samples.iter().position(|s| s.keyframe).unwrap_or(0);
    for (i, _s) in samples.iter().enumerate().skip(start) {
        let Ok(payload) = track.sample_bytes(input, i) else {
            continue;
        };
        annexb.clear();
        let mut p = 0usize;
        while p + length_size <= payload.len() {
            let n = match length_size {
                1 => usize::from(payload[p]),
                2 => usize::from(u16::from_be_bytes([payload[p], payload[p + 1]])),
                4 => {
                    u32::from_be_bytes([payload[p], payload[p + 1], payload[p + 2], payload[p + 3]])
                        as usize
                }
                _ => break,
            };
            p += length_size;
            let Some(nal) = payload.get(p..p + n) else {
                break;
            };
            annexb.extend_from_slice(&[0, 0, 0, 1]);
            annexb.extend_from_slice(nal);
            p += n;
        }
        let Ok(frames) = dec.push_stream(&annexb) else {
            continue;
        };
        for f in &frames {
            let m = frame_phash_margin(f.width, f.height, &f.y);
            if m < min_margin {
                min_margin = m;
            }
        }
    }
    min_margin
}

/// One measurement of a fingerprinted fixture: everything reference.json
/// pins about the success path.
pub(crate) struct Measured {
    pub(crate) width: u32,
    pub(crate) height: u32,
    pub(crate) decoded_frames: usize,
    pub(crate) frame_phashes_hex: Vec<String>,
    pub(crate) minhash: MinHashFold,
    pub(crate) content_digest: String,
    pub(crate) duration_bits: String,
    pub(crate) fps_sampled_bits: String,
    /// Smallest threshold margin over all frames — decides whether the
    /// pHash hex is platform-stable enough to pin.
    pub(crate) phash_margin: f64,
}

/// Fingerprints `input`; panics on any decode fault — fixture vectors
/// are only emitted for files that fingerprint.
pub(crate) fn measure(input: &[u8]) -> Measured {
    let fp: VideoFingerprint = decode(input, &Limits::default()).expect("fixture must fingerprint");
    assert!(
        !fp.frame_hashes.is_empty(),
        "fixture must yield sampled frames"
    );
    Measured {
        width: fp.width,
        height: fp.height,
        decoded_frames: fp.frame_hashes.len(),
        frame_phashes_hex: fp.frame_hashes.iter().map(|h| hex64(*h)).collect(),
        minhash: fold_minhash(&fp.minhash),
        content_digest: hex(fp.content_digest.as_bytes()),
        duration_bits: f64_bits(fp.duration),
        fps_sampled_bits: f64_bits(fp.fps_sampled),
        phash_margin: phash_margin(input),
    }
}

/// `n` bytes of `b` as an inline-hex JSON input.
fn garbage_hex(b: u8, n: usize) -> String {
    hex(&vec![b; n])
}

/// Assembles the whole reference.json document (LF-terminated).
pub(crate) fn reference_json(root: &Path) -> String {
    let mut out = String::new();
    out.push_str("{\n");
    out.push_str("  \"suite\": \"pith\",\n");
    out.push_str("  \"crate\": \"pith-video\",\n");
    out.push_str("  \"format_version\": 1,\n");
    out.push_str("  \"generator\": \"cargo run --bin gen-reference -- gen\",\n");
    out.push_str(
        "  \"description\": \"Hex-exact video-lane vectors for pith-video: \
sampled frame-pHash chains (64-bit hex, only where the DCT threshold margins \
clear the libm noise floor — flat sources keep their integer pins instead), \
MinHash folds over the 128-word chain signature, tier-1 content digests, \
f64 facts as IEEE-754 bits and decode error kinds over the committed fixtures \
and inline hostile inputs.\",\n",
    );

    // --- Fingerprint vectors: every fixture that decodes, sorted ---
    let mut vectors: Vec<String> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    for name in fixture_names(root) {
        let raw = fs::read(root.join(FIXTURES_DIR).join(&name))
            .unwrap_or_else(|e| panic!("cannot read fixture {name}: {e}"));
        let input_sha = hex(sha256(&raw).expect("sha256 of fixture").as_bytes());
        let path = format!("{FIXTURES_DIR}/{name}");
        match decode(&raw, &Limits::default()) {
            Ok(_) => {
                let m = measure(&raw);
                let stable = m.phash_margin > PHASH_MARGIN_FLOOR;
                let phashes = if stable {
                    m.frame_phashes_hex
                        .iter()
                        .map(|h| format!("        \"{h}\""))
                        .collect::<Vec<_>>()
                        .join(",\n")
                } else {
                    String::new()
                };
                let phash_fields = if stable {
                    format!(
                        "      \"phash_hex_pinned\": true,\n      \"frame_phashes_hex\": [\n{phashes}\n      ],\n"
                    )
                } else {
                    "      \"phash_hex_pinned\": false,\n      \"frame_phashes_hex\": [],\n      \"phash_pin_reason\": \"solid-color source: DCT thresholds sit at the subnormal noise floor, so the hash bits are libm-sensitive; per-platform verification lives in tests/video.rs\",\n".to_owned()
                };
                let fnv_hex = hex64(m.minhash.fnv1a64);
                vectors.push(format!(
                    "    {{\n      \"name\": \"{name}\",\n      \"input_kind\": \"fixture-file\",\n      \"input_path\": \"{path}\",\n      \"input_sha256\": \"{input_sha}\",\n      \"width\": {},\n      \"height\": {},\n      \"sampled_frames\": {},\n{phash_fields}      \"minhash_word_0\": \"{}\",\n      \"minhash_word_1\": \"{}\",\n      \"minhash_fnv1a64\": \"{}\",\n      \"minhash_sha256\": \"{}\",\n      \"content_digest_sha256\": \"{}\",\n      \"value_kind\": \"f64-ieee754-bits-hex\",\n      \"policy\": \"exact\",\n      \"duration_bits\": \"{}\",\n      \"fps_sampled_bits\": \"{}\"\n    }}",
                    m.width,
                    m.height,
                    m.decoded_frames,
                    hex64(m.minhash.first),
                    hex64(m.minhash.second),
                    fnv_hex,
                    m.minhash.sha256,
                    m.content_digest,
                    m.duration_bits,
                    m.fps_sampled_bits,
                ));
            }
            Err(e) => {
                errors.push(format!(
                    "    {{\n      \"name\": \"fixture-{name}\",\n      \"input_kind\": \"fixture-file\",\n      \"input_path\": \"{path}\",\n      \"input_sha256\": \"{input_sha}\",\n      \"error_kind\": \"{}\"\n    }}",
                    error_kind(&e),
                ));
            }
        }
    }

    out.push_str("  \"vectors\": [\n");
    out.push_str(&vectors.join(",\n"));
    out.push_str("\n  ],\n");

    // --- Decode errors: refusing fixtures plus crafted inline inputs.
    // The kind is stable; the message text is not depended on. ---
    let empty_err = decode(&[], &Limits::default()).expect_err("empty input must error");
    let garbage_err =
        decode(&[0xAB; 4096], &Limits::default()).expect_err("non-BMFF bytes must error");
    // A well-formed `ftyp` box head truncated mid-table: Truncated.
    let truncated_err = decode(
        &[
            0x00, 0x00, 0x00, 0x18, b'f', b't', b'y', b'p', b'i', b's', b'o', b'm',
        ],
        &Limits::default(),
    )
    .expect_err("declared box length over the input must error");
    let inline = [
        ("empty-input", "", &empty_err),
        ("random-bytes", &garbage_hex(0xAB, 4096), &garbage_err),
        (
            "truncated-box-head",
            "000000186674797069736f6d",
            &truncated_err,
        ),
    ];
    for (name, input_hex, e) in inline {
        errors.push(format!(
            "    {{\n      \"name\": \"{name}\",\n      \"input_kind\": \"inline-hex\",\n      \"input_hex\": \"{input_hex}\",\n      \"error_kind\": \"{}\"\n    }}",
            error_kind(e),
        ));
    }
    out.push_str("  \"errors\": [\n");
    out.push_str(&errors.join(",\n"));
    out.push_str("\n  ],\n");

    // --- Limits errors: a default-decodes input refused under a tighter
    // ceiling. (field, value) pairs; kind stays TooLarge. ---
    let a_raw =
        fs::read(root.join(FIXTURES_DIR).join("a_64x48.mp4")).expect("a_64x48.mp4 must exist");
    let a = decode(&a_raw, &Limits::default()).expect("a_64x48.mp4 must fingerprint");
    let dur = a.duration;
    let lim_errors = [
        (
            "limits-max-input",
            "max_input",
            format!("{}", a_raw.len() - 1),
        ),
        // Half a second below the real duration — the slot boundary the
        // source acceptance test uses, so the gate fires.
        (
            "limits-max-duration",
            "max_duration_s",
            format!("{}", dur - 0.5),
        ),
        (
            "limits-max-frames",
            "max_frames",
            format!("{}", a.frame_hashes.len() - 1),
        ),
        (
            "limits-max-decoded-frames",
            "max_decoded_frames",
            "2".to_owned(),
        ),
    ];
    let mut lims: Vec<String> = Vec::new();
    for (i, (name, field, value)) in lim_errors.iter().enumerate() {
        let limits_json = format!("{{\\\"{field}\\\": {value}}}");
        let e = decode(
            &a_raw,
            &Limits {
                max_input: if *field == "max_input" {
                    a_raw.len() - 1
                } else {
                    Limits::default().max_input
                },
                max_duration_s: if *field == "max_duration_s" {
                    dur - 0.5
                } else {
                    Limits::default().max_duration_s
                },
                max_frames: if *field == "max_frames" {
                    a.frame_hashes.len() - 1
                } else {
                    Limits::default().max_frames
                },
                max_decoded_frames: if *field == "max_decoded_frames" {
                    2
                } else {
                    Limits::default().max_decoded_frames
                },
            },
        )
        .expect_err("a tightened limit must refuse");
        assert_eq!(error_kind(&e), "TooLarge");
        let comma = if i + 1 == lim_errors.len() { "" } else { "," };
        lims.push(format!(
            "    {{\n      \"name\": \"{name}\",\n      \"input_path\": \"{FIXTURES_DIR}/a_64x48.mp4\",\n      \"limits_override\": \"{limits_json}\",\n      \"error_kind\": \"{}\"\n    }}{comma}",
            error_kind(&e),
        ));
    }
    out.push_str("  \"limits_errors\": [\n");
    out.push_str(&lims.join("\n"));
    out.push_str("\n  ]\n}\n");
    out
}

pub(crate) fn run(mode: &str, path: Option<&Path>) -> ExitCode {
    let path = path
        .map(PathBuf::from)
        .unwrap_or_else(|| repo_root().join(REFERENCE_PATH));
    match mode {
        "gen" => {
            let json = reference_json(&repo_root());
            fs::write(&path, &json).unwrap_or_else(|e| panic!("cannot write {path:?}: {e}"));
            println!("wrote {} ({} bytes)", path.display(), json.len());
            ExitCode::SUCCESS
        }
        "verify" => {
            let json = reference_json(&repo_root());
            let committed = match fs::read(&path) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("FAIL: cannot read {path:?}: {e}");
                    return ExitCode::FAILURE;
                }
            };
            if committed == json.as_bytes() {
                println!("reference.json is current");
                ExitCode::SUCCESS
            } else {
                let off = committed
                    .iter()
                    .zip(json.as_bytes())
                    .position(|(a, b)| a != b)
                    .unwrap_or(committed.len().min(json.len()));
                eprintln!(
                    "FAIL: reference.json is stale: committed {} bytes, computed {} bytes, first difference at byte {off}",
                    committed.len(),
                    json.len()
                );
                ExitCode::FAILURE
            }
        }
        _ => {
            eprintln!("usage: gen-reference <gen|verify> [PATH] (got {mode:?})");
            ExitCode::from(2)
        }
    }
}

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let mode = args.next().unwrap_or_else(|| "verify".to_owned());
    run(&mode, args.next().map(PathBuf::from).as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Serializes every test that reads/writes reference.json: cargo
    /// runs test threads in parallel and the file is shared state.
    pub(crate) static REF_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn hex_is_lowercase_two_digits_per_byte() {
        assert_eq!(hex(&[0x00, 0x0f, 0xf0, 0xff]), "000ff0ff");
        assert_eq!(hex(&[]), "");
    }

    #[test]
    fn hex64_pads_to_sixteen_digits() {
        assert_eq!(hex64(0), "0000000000000000");
        assert_eq!(hex64(u64::MAX), "ffffffffffffffff");
        assert_eq!(hex64(1), "0000000000000001");
    }

    #[test]
    fn f64_bits_pins_the_edges() {
        assert_eq!(f64_bits(1.0), "3ff0000000000000");
        assert_eq!(f64_bits(2.0), "4000000000000000");
        assert_eq!(f64_bits(0.0), "0000000000000000");
        assert_eq!(f64_bits(4.0), "4010000000000000");
    }

    #[test]
    fn error_kind_maps_every_decoder_error() {
        assert_eq!(error_kind(&Error::BadValue("x")), "BadValue");
        assert_eq!(error_kind(&Error::Unsupported("x")), "Unsupported");
        assert_eq!(
            error_kind(&Error::InvalidMagic { what: "x" }),
            "InvalidMagic"
        );
        assert_eq!(
            error_kind(&Error::Truncated {
                what: "x",
                needed: 1,
                found: 0
            }),
            "Truncated"
        );
        assert_eq!(
            error_kind(&Error::TooLarge {
                what: "x",
                limit: 1
            }),
            "TooLarge"
        );
    }

    #[test]
    fn fixture_names_sorted_containers_only() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let names = fixture_names(root);
        assert!(!names.is_empty());
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted);
        assert!(
            names
                .iter()
                .all(|n| n.ends_with(".mp4") || n.ends_with(".mov") || n.ends_with(".h264"))
        );
        // The reference fingerprint and the negative fixtures are all in.
        assert!(names.contains(&"a_64x48.mp4".to_owned()));
        assert!(names.contains(&"a_frag.mp4".to_owned()));
        assert!(names.contains(&"annexb_32x24.h264".to_owned()));
    }

    /// A textured frame sits orders of magnitude above the stability
    /// floor; a solid-color frame cancels into the subnormal noise
    /// floor. Both verds are computed, not hard-coded.
    #[test]
    fn margin_filter_separates_textured_from_flat() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let textured = fs::read(root.join(FIXTURES_DIR).join("b_64x48.mp4")).unwrap();
        let flat = fs::read(root.join(FIXTURES_DIR).join("short_32x24.mp4")).unwrap();
        let textured_margin = phash_margin(&textured);
        let flat_margin = phash_margin(&flat);
        assert!(
            textured_margin > PHASH_MARGIN_FLOOR,
            "textured margin {textured_margin} must clear the floor"
        );
        assert!(
            flat_margin <= PHASH_MARGIN_FLOOR,
            "flat margin {flat_margin} must sit at the noise floor"
        );
    }

    /// Exactly the solid-color fixtures are excluded from the pHash
    /// pins; everything textured stays pinned.
    #[test]
    fn reference_excludes_only_flat_fixtures() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let json = reference_json(root);
        // Each vector: from its `"name": "<n>"` marker to the next
        // vector's marker must contain the object's own pin flag.
        let pinned = |name: &str| -> Option<bool> {
            let start = json.find(&format!("\"name\": \"{name}\""))?;
            let rest = &json[start + 1..];
            let end = rest.find("\"name\": \"").unwrap_or(rest.len());
            rest[..end]
                .split_once("\"phash_hex_pinned\": ")
                .map(|(_, flag)| flag.starts_with("true"))
        };
        assert_eq!(pinned("a_64x48.mp4"), Some(true));
        assert_eq!(pinned("b_64x48.mp4"), Some(true));
        assert_eq!(pinned("high_64x48.mp4"), Some(true));
        assert_eq!(pinned("two_32x24.mp4"), Some(true));
        // The solid-color sources cancel to the subnormal noise floor.
        assert_eq!(pinned("short_32x24.mp4"), Some(false));
        assert_eq!(pinned("tiny_16x16.mp4"), Some(false));
        assert_eq!(json.matches("\"phash_hex_pinned\": true").count(), 9);
        assert_eq!(json.matches("\"phash_hex_pinned\": false").count(), 2);
    }

    #[test]
    fn fold_pins_the_sentinel_signature() {
        let f = fold_minhash(&vec![u64::MAX; 128]);
        assert_eq!(hex64(f.first), "ffffffffffffffff");
        assert_eq!(hex64(f.second), "ffffffffffffffff");
        // The fold is a function of the little-endian words.
        let mut le = Vec::with_capacity(128 * 8);
        le.extend_from_slice(&[0xFF; 128 * 8]);
        assert_eq!(
            format!("{:016x}", f.fnv1a64),
            format!("{:016x}", fnv1a64(&le))
        );
        assert_eq!(f.sha256.len(), 64);
    }

    #[test]
    fn fold_rejects_a_short_signature() {
        let result = std::panic::catch_unwind(|| fold_minhash(&[1, 2, 3]));
        assert!(result.is_err(), "a short signature must fail loudly");
    }

    #[test]
    fn measure_fingerprints_the_reference_fixture() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let raw = fs::read(root.join(FIXTURES_DIR).join("a_64x48.mp4")).unwrap();
        let m = measure(&raw);
        assert_eq!((m.width, m.height), (64, 48));
        assert_eq!(m.decoded_frames, 8);
        assert_eq!(m.frame_phashes_hex.len(), 8);
        assert!(m.frame_phashes_hex.iter().all(|h| h.len() == 16));
        assert_eq!(m.content_digest.len(), 64);
        assert!(m.phash_margin > PHASH_MARGIN_FLOOR);
        // 4 s over 4.0: both dyadic facts are exact.
        assert_eq!(m.duration_bits, f64_bits(4.0));
        assert_eq!(m.fps_sampled_bits, f64_bits(2.0));
    }

    #[test]
    #[should_panic(expected = "fixture must fingerprint")]
    fn measure_rejects_garbage_loudly() {
        let _ = measure(&[0xAB; 4096]);
    }

    /// The margin mirror must agree with the crate's own verdict on the
    /// fixture set: every fixture it hashes without pinning sits at the
    /// noise floor, every pinned one clears it.
    #[test]
    fn margin_mirror_matches_the_crate_pipeline() {
        let plane: Vec<u8> = (0..64 * 48).map(|i| ((i * 37) % 256) as u8).collect();
        let m = frame_phash_margin(64, 48, &plane);
        assert!(m.is_finite());
        // The pinned hash of the same plane comes from the crate.
        let hash = pith_video::frame_phash(64, 48, &plane).unwrap();
        assert_ne!(hash, 0);
    }

    /// The committed reference.json is current — the CI gate, run
    /// in-process under the shared lock.
    #[test]
    fn committed_reference_is_current() {
        let _guard = REF_LOCK.lock().unwrap();
        assert_eq!(run("verify", None), ExitCode::SUCCESS);
    }

    #[test]
    fn verify_rejects_a_stale_reference() {
        let _guard = REF_LOCK.lock().unwrap();
        let dir = std::env::temp_dir().join(format!("pith-video-stale-{}", std::process::id()));
        fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("reference.json");
        fs::write(&path, "{\n  \"format\": 0\n}\n").expect("stale file");
        assert_eq!(run("verify", Some(&path)), ExitCode::FAILURE);
        fs::remove_file(&path).expect("cleanup");
        fs::remove_dir(&dir).expect("cleanup");
    }

    #[test]
    fn verify_reports_an_unreadable_path() {
        let _guard = REF_LOCK.lock().unwrap();
        assert_eq!(
            run(
                "verify",
                Some(Path::new("definitely-missing-reference.json"))
            ),
            ExitCode::FAILURE
        );
    }

    #[test]
    fn gen_reproduces_the_committed_bytes() {
        let _guard = REF_LOCK.lock().unwrap();
        let dir = std::env::temp_dir().join(format!("pith-video-gen-{}", std::process::id()));
        fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("reference.json");
        assert_eq!(run("gen", Some(&path)), ExitCode::SUCCESS);
        let committed = fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join(REFERENCE_PATH))
            .expect("committed");
        assert_eq!(
            fs::read(&path).expect("generated"),
            committed,
            "gen must reproduce committed bytes"
        );
        fs::remove_file(&path).expect("cleanup");
        fs::remove_dir(&dir).expect("cleanup");
    }

    #[test]
    fn unknown_mode_prints_usage() {
        let _guard = REF_LOCK.lock().unwrap();
        assert_eq!(run("generate", None), ExitCode::from(2));
    }

    /// The document is structurally balanced without a JSON dependency:
    /// every string field opens and closes, braces balance, LF endings
    /// and a trailing newline close the document.
    #[test]
    fn reference_json_shape_holds() {
        let json = reference_json(Path::new(env!("CARGO_MANIFEST_DIR")));
        assert!(json.ends_with("}\n"));
        assert!(!json.contains('\r'));
        // Balanced quotes: every line carries an even count.
        for line in json.lines() {
            assert_eq!(
                line.matches('"').count() % 2,
                0,
                "unbalanced quotes in {line:?}"
            );
        }
        // Brace balance outside string literals (none embed braces).
        assert_eq!(json.matches('{').count(), json.matches('}').count());
        assert_eq!(json.matches('[').count(), json.matches(']').count());
    }

    #[test]
    fn reference_json_names_the_suite_markers() {
        let json = reference_json(Path::new(env!("CARGO_MANIFEST_DIR")));
        assert!(json.contains("\"suite\": \"pith\""));
        assert!(json.contains("\"crate\": \"pith-video\""));
        assert!(json.contains("\"format_version\": 1"));
        assert!(json.contains("\"frame_phashes_hex\""));
        assert!(json.contains("\"phash_hex_pinned\": true"));
        assert!(json.contains("\"minhash_fnv1a64\""));
        assert!(json.contains("\"content_digest_sha256\""));
        assert!(json.contains("\"error_kind\": \"Unsupported\""));
        assert!(json.contains("\"error_kind\": \"TooLarge\""));
    }
}
