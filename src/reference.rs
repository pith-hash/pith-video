//! The canonical fingerprint serialization behind `reference.json`,
//! re-expressed as library code so the vector generator and the C ABI
//! surface ([`crate::ffi`]) share one implementation.
//!
//! Every vector in `reference.json` is computed through the crate's
//! public [`decode`](crate::decode) API from a committed fixture
//! (`tests/fixtures/*.mp4`/`.mov`); the [`VideoFingerprint`] is
//! serialized into a canonical byte stream by [`canonical_bytes`] —
//! the exact stream [`pith_video_fingerprint`](crate::ffi::pith_video_fingerprint)
//! hands to the language SDKs — and the MinHash signature is folded
//! into the compact [`MinHashFold`] whose fields are what
//! `minhash_word_0/1`, `minhash_fnv1a64` and `minhash_sha256` pin.
//!
//! # Wire format (canonical stream)
//!
//! Every multi-byte field is **big-endian**, except the 128 MinHash
//! words, which are **little-endian**: the pinned `minhash_fnv1a64` /
//! `minhash_sha256` folds hash the little-endian word bytes, so the
//! stream carries them in exactly the form those folds consume.
//!
//! 1. `width` as `u32` BE, `height` as `u32` BE, `sampled_frames`
//!    (`frame_hashes.len()`) as `u32` BE;
//! 2. `duration` as the `f64` IEEE-754 bit pattern, `u64` BE;
//!    `fps_sampled` likewise BE;
//! 3. the frame pHashes, one `u64` BE each, presentation order;
//! 4. the MinHash signature: exactly 128 `u64` words, little-endian
//!    each (1024 bytes);
//! 5. the tier-1 content digest, raw 32 bytes.

use crate::VideoFingerprint;
use pith_digest::{fnv1a64, sha256};

/// Lowercase hex of `bytes`.
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// The 128-word MinHash signature folded for compact transport: first
/// two words verbatim, then FNV-1a 64 and SHA-256 over all 128
/// little-endian words — the same fold shape the text lane pins.
pub struct MinHashFold {
    /// `minhash[0]`, verbatim.
    pub first: u64,
    /// `minhash[1]`, verbatim.
    pub second: u64,
    /// FNV-1a 64 over the 1024 little-endian word bytes.
    pub fnv1a64: u64,
    /// Lowercase-hex SHA-256 over the same 1024 bytes.
    pub sha256: String,
}

/// Folds one 128-word MinHash signature for compact transport (see
/// [`MinHashFold`]). Panics when `sig` is not exactly 128 words — the
/// length is part of the contract.
#[must_use]
pub fn fold_minhash(sig: &[u64]) -> MinHashFold {
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

/// Serializes one decoded video fingerprint into the canonical byte
/// stream the SDK wire format is defined over (see the module docs for
/// the exact layout). Panics when `fp.minhash` is not exactly 128
/// words — the width is part of the wire contract.
#[must_use]
pub fn canonical_bytes(fp: &VideoFingerprint) -> Vec<u8> {
    assert_eq!(
        fp.minhash.len(),
        128,
        "minhash width is part of the wire contract"
    );
    let mut out = Vec::with_capacity(28 + fp.frame_hashes.len() * 8 + 128 * 8 + 32);
    out.extend_from_slice(&fp.width.to_be_bytes());
    out.extend_from_slice(&fp.height.to_be_bytes());
    out.extend_from_slice(&(fp.frame_hashes.len() as u32).to_be_bytes());
    out.extend_from_slice(&fp.duration.to_bits().to_be_bytes());
    out.extend_from_slice(&fp.fps_sampled.to_bits().to_be_bytes());
    for h in &fp.frame_hashes {
        out.extend_from_slice(&h.to_be_bytes());
    }
    for w in &fp.minhash {
        out.extend_from_slice(&w.to_le_bytes());
    }
    out.extend_from_slice(fp.content_digest.as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::{MinHashFold, canonical_bytes, fold_minhash, hex};
    use crate::VideoFingerprint;
    use pith_digest::{Digest, fnv1a64, sha256};

    /// `fold_minhash` over a synthetic 128-word signature equals the
    /// manual FNV-1a 64 / SHA-256 over the same little-endian blob.
    #[test]
    fn fold_minhash_matches_a_manual_fold() {
        let sig: Vec<u64> = (0..128)
            .map(|i| 0x0100_0000_0000_0001_u64.wrapping_mul(i as u64 + 1))
            .collect();
        let mut le = Vec::with_capacity(128 * 8);
        for w in &sig {
            le.extend_from_slice(&w.to_le_bytes());
        }
        let f = fold_minhash(&sig);
        assert_eq!(f.first, sig[0]);
        assert_eq!(f.second, sig[1]);
        assert_eq!(f.fnv1a64, fnv1a64(&le));
        assert_eq!(f.sha256, hex(sha256(&le).expect("sha256").as_bytes()));
    }

    /// A short signature fails loudly — the length is the contract.
    #[test]
    #[should_panic(expected = "signature length is part of the contract")]
    fn fold_rejects_a_short_signature() {
        let _ = fold_minhash(&[1, 2, 3]);
    }

    /// `hex` is the lowercase two-digits-per-byte encoder the fold's
    /// SHA-256 field and the generator share.
    #[test]
    fn hex_is_lowercase_two_digits_per_byte() {
        assert_eq!(hex(&[0x00, 0x0f, 0xf0, 0xff]), "000ff0ff");
        assert_eq!(hex(&[]), "");
    }

    /// The canonical stream is the documented wire contract: BE header
    /// and frame hashes, LE minhash words, raw digest tail — and a
    /// parse of the stream re-reads every field to its source value.
    #[test]
    fn canonical_bytes_layout_is_the_wire_contract() {
        let mut minhash = vec![0u64; 128];
        minhash[0] = 0x0011_2233_4455_6677;
        minhash[1] = 0x8899_aabb_ccdd_eeff;
        minhash[127] = 0x0102_0304_0506_0708;
        let fp = VideoFingerprint {
            frame_hashes: vec![0x1122_3344_5566_7788, 0x99aa_bbcc_ddee_ff00],
            minhash,
            duration: 4.0,
            fps_sampled: 2.0,
            width: 3,
            height: 2,
            content_digest: Digest::from_bytes([0xa5; 32]),
        };
        let raw = canonical_bytes(&fp);
        assert_eq!(raw.len(), 28 + 2 * 8 + 128 * 8 + 32);

        // Header: width, height, sampled_frames, both f64 bit patterns.
        assert_eq!(&raw[0..4], &[0, 0, 0, 3]);
        assert_eq!(&raw[4..8], &[0, 0, 0, 2]);
        assert_eq!(&raw[8..12], &[0, 0, 0, 2]);
        assert_eq!(&raw[12..20], &4.0f64.to_bits().to_be_bytes());
        assert_eq!(&raw[20..28], &2.0f64.to_bits().to_be_bytes());

        // Frame hashes big-endian, presentation order.
        assert_eq!(&raw[28..36], &0x1122_3344_5566_7788u64.to_be_bytes());
        assert_eq!(&raw[36..44], &0x99aa_bbcc_ddee_ff00u64.to_be_bytes());

        // Minhash words little-endian — first, second and last.
        let base = 28 + 2 * 8;
        assert_eq!(
            &raw[base..base + 8],
            &0x0011_2233_4455_6677u64.to_le_bytes()
        );
        assert_eq!(
            &raw[base + 8..base + 16],
            &0x8899_aabb_ccdd_eeffu64.to_le_bytes()
        );
        assert_eq!(
            &raw[base + 1016..base + 1024],
            &0x0102_0304_0506_0708u64.to_le_bytes()
        );

        // Raw digest tail.
        assert_eq!(&raw[raw.len() - 32..], &[0xa5; 32]);

        // Roundtrip parse: every field re-reads to its source value.
        let be32 = |r: &[u8]| u32::from_be_bytes(r.try_into().expect("4 bytes"));
        let be64 = |r: &[u8]| u64::from_be_bytes(r.try_into().expect("8 bytes"));
        let le64 = |r: &[u8]| u64::from_le_bytes(r.try_into().expect("8 bytes"));
        assert_eq!(be32(&raw[0..4]), fp.width);
        assert_eq!(be32(&raw[4..8]), fp.height);
        assert_eq!(be32(&raw[8..12]), 2);
        assert_eq!(f64::from_bits(be64(&raw[12..20])), fp.duration);
        assert_eq!(f64::from_bits(be64(&raw[20..28])), fp.fps_sampled);
        assert_eq!(be64(&raw[28..36]), fp.frame_hashes[0]);
        assert_eq!(le64(&raw[base..base + 8]), fp.minhash[0]);
        assert_eq!(raw[raw.len() - 32..], fp.content_digest.as_bytes().to_vec());
    }

    /// A wrong minhash width fails loudly — the width is the wire
    /// contract.
    #[test]
    #[should_panic(expected = "minhash width is part of the wire contract")]
    fn canonical_bytes_rejects_a_wrong_minhash_width() {
        let fp = VideoFingerprint {
            frame_hashes: vec![],
            minhash: vec![0; 4],
            duration: 0.0,
            fps_sampled: 0.0,
            width: 0,
            height: 0,
            content_digest: Digest::from_bytes([0; 32]),
        };
        let _ = canonical_bytes(&fp);
    }

    /// The fold type stays nameable for the generator's imports.
    #[test]
    fn minhash_fold_type_is_importable() {
        let f: MinHashFold = fold_minhash(&vec![7u64; 128]);
        assert_eq!(f.first, 7);
    }
}
