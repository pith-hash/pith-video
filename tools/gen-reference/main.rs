//! Regenerates and verifies `reference.json`: the hex-exact video-lane
//! vectors of the pith suite. Per fingerprintable fixture under
//! `tests/fixtures/` (deterministic sorted order) it pins the sampled
//! frame-pHash chain (16-digit hex per 64-bit hash), the MinHash fold
//! over the 128-word chain signature, the tier-1 content digest and the
//! `f64` facts (duration, achieved fps) as raw IEEE-754 bits; the
//! refusing fixtures and crafted hostile inputs are pinned as decode
//! error kinds.
//!
//! `gen-reference gen [PATH]` rewrites the file; `gen-reference verify
//! [PATH]` recomputes it and fails on any difference. CI runs `verify`
//! so a port drift (pHash pipeline, MinHash seeding, sampler) cannot
//! land silently, and CD ships the file with the SDK artifacts as the
//! cross-language oracle.
//!
//! The corpus is byte-stable across platforms: the sampled pHashes are
//! bit-exact `u64`s, the MinHash fold is integer-only, and the `f64`
//! values are single IEEE-754 divisions (correctly rounded, so the hex
//! bit pattern is identical everywhere).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use pith_digest::{Error, fnv1a64, sha256};
use pith_video::{Limits, VideoFingerprint, decode};

const FIXTURES_DIR: &str = "tests/fixtures";
const REFERENCE_PATH: &str = "reference.json";

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
sampled frame-pHash chains (64-bit hex), MinHash folds over the 128-word \
chain signature, tier-1 content digests, f64 facts as IEEE-754 bits and \
decode error kinds over the committed fixtures and inline hostile inputs.\",\n",
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
                let phashes = m
                    .frame_phashes_hex
                    .iter()
                    .map(|h| format!("        \"{h}\""))
                    .collect::<Vec<_>>()
                    .join(",\n");
                let fnv_hex = hex64(m.minhash.fnv1a64);
                vectors.push(format!(
                    "    {{\n      \"name\": \"{}\",\n      \"input_kind\": \"fixture-file\",\n      \"input_path\": \"{path}\",\n      \"input_sha256\": \"{input_sha}\",\n      \"width\": {},\n      \"height\": {},\n      \"sampled_frames\": {},\n      \"frame_phashes_hex\": [\n{phashes}\n      ],\n      \"minhash_word_0\": \"{}\",\n      \"minhash_word_1\": \"{}\",\n      \"minhash_fnv1a64\": \"{}\",\n      \"minhash_sha256\": \"{}\",\n      \"content_digest_sha256\": \"{}\",\n      \"value_kind\": \"f64-ieee754-bits-hex\",\n      \"policy\": \"exact\",\n      \"duration_bits\": \"{}\",\n      \"fps_sampled_bits\": \"{}\"\n    }}",
                    &name,
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
                    "    {{\n      \"name\": \"fixture-{}\",\n      \"input_kind\": \"fixture-file\",\n      \"input_path\": \"{path}\",\n      \"input_sha256\": \"{input_sha}\",\n      \"error_kind\": \"{}\"\n    }}",
                    &name,
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
        // 4 s over 4.0: both dyadic facts are exact.
        assert_eq!(m.duration_bits, f64_bits(4.0));
        assert_eq!(m.fps_sampled_bits, f64_bits(2.0));
    }

    #[test]
    #[should_panic(expected = "fixture must fingerprint")]
    fn measure_rejects_garbage_loudly() {
        let _ = measure(&[0xAB; 4096]);
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
        assert!(json.contains("\"minhash_fnv1a64\""));
        assert!(json.contains("\"content_digest_sha256\""));
        assert!(json.contains("\"error_kind\": \"Unsupported\""));
        assert!(json.contains("\"error_kind\": \"TooLarge\""));
    }
}
