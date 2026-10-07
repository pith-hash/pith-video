//! The C ABI surface of `pith-video`: the entry points the Python
//! (ctypes), Node (koffi) and Go (cgo) SDKs bind through.
//!
//! The suite's FFI convention, defined by this module and mirrored by
//! every `pith-*` cdylib:
//!
//! * one flat set of `#[unsafe(no_mangle)] pub unsafe extern "C"`
//!   functions — raw pointers plus lengths, no structs across the
//!   boundary;
//! * every function returns a status code (see the constants below),
//!   never a `Result`, never a panic: a `panic = "abort"` cdylib must
//!   not be reachable from a foreign caller;
//! * an operation either hands ownership to the caller (and ships a
//!   matching `_free` — [`pith_video_free`] here) or writes into
//!   caller-provided out-parameters;
//! * the `unsafe` allowance is confined to this module; every core
//!   module stays unsafe-free behind the crate-root `#![deny]`.
//!
//! Decoding uses the crate's conservative default [`Limits`] (256 MiB
//! of file, ten-minute tracks, 8192 sampled frames) — a hashing
//! pipeline never wants an unbounded decode, and the FFI surface is no
//! exception.
//!
//! # Wire format (canonical stream)
//!
//! [`pith_video_fingerprint`] hands back the canonical byte stream
//! [`canonical_bytes`](crate::reference::canonical_bytes) produces —
//! the bytes every `reference.json` vector is defined over:
//!
//! * `width` `u32` **BE**, `height` `u32` **BE**, `sampled_frames`
//!   `u32` **BE**;
//! * `duration` as the `f64` IEEE-754 bit pattern, `u64` **BE**;
//!   `fps_sampled` likewise **BE**;
//! * `sampled_frames` frame pHashes, `u64` **BE** each, presentation
//!   order;
//! * exactly 128 MinHash words, `u64` **little-endian** each — LE
//!   because the pinned `minhash_fnv1a64`/`minhash_sha256` folds hash
//!   the little-endian word bytes;
//! * the tier-1 content digest, raw 32 bytes.

#![allow(unsafe_code)]

use crate::reference::canonical_bytes;
use crate::{Limits, decode};

/// Status: success.
pub const PITH_OK: i32 = 0;
/// Status: a caller argument is invalid — a null pointer.
pub const PITH_E_INVALID: i32 = -1;
/// Status: the core decoder refused the input (malformed container or
/// H.264 stream, unsupported codec, fragmented MP4, or a default
/// [`Limits`] bound exceeded).
pub const PITH_E_REJECTED: i32 = -2;

/// Fingerprints a whole ISO-BMFF file (mp4/mov, H.264 video track)
/// into the canonical byte stream the `reference.json` vectors are
/// defined over.
///
/// `data` points at `len` bytes of the complete file. On success the
/// function allocates a buffer, writes its address through `out`, its
/// length through `out_len`, and returns [`PITH_OK`]; the caller owns
/// the buffer and must release it with [`pith_video_free`], passing
/// back the same pointer *and* length. The layout is documented in the
/// module docs: big-endian header and frame hashes, little-endian
/// MinHash words, raw digest tail.
///
/// # Safety
///
/// `data` must point to `len` readable bytes; `out` to one writable
/// pointer; `out_len` to one writable `usize`. All must stay valid for
/// the duration of the call; the function retains nothing.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pith_video_fingerprint(
    data: *const u8,
    len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    if data.is_null() || out.is_null() || out_len.is_null() {
        return PITH_E_INVALID;
    }
    let bytes = unsafe { core::slice::from_raw_parts(data, len) };
    match fingerprint_and_serialize(bytes) {
        Ok(canonical) => {
            let len = canonical.len();
            // Hand the exact-length buffer to the caller; `pith_video_free`
            // reconstructs the boxed slice from the same length.
            let ptr = Box::into_raw(canonical.into_boxed_slice());
            unsafe {
                *out = ptr.cast::<u8>();
                *out_len = len;
            }
            PITH_OK
        }
        Err(status) => status,
    }
}

/// Releases a buffer handed out by [`pith_video_fingerprint`].
///
/// # Safety
///
/// `ptr` must be a pointer returned by [`pith_video_fingerprint`]
/// with the `out_len` value that came back with it, and must not have
/// been released (or otherwise freed) before. Null is accepted and
/// ignored, so callers can free unconditionally on the error path.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pith_video_free(ptr: *mut u8, len: usize) {
    if ptr.is_null() {
        return;
    }
    let slice = unsafe { core::slice::from_raw_parts_mut(ptr, len) };
    drop(unsafe { Box::from_raw(slice) });
}

/// The safe core of [`pith_video_fingerprint`]: decode, then
/// serialize canonically. Decoding failures map to
/// [`PITH_E_REJECTED`].
fn fingerprint_and_serialize(bytes: &[u8]) -> Result<Vec<u8>, i32> {
    let fp = decode(bytes, &Limits::default()).map_err(|_| PITH_E_REJECTED)?;
    Ok(canonical_bytes(&fp))
}

#[cfg(test)]
mod tests {
    use super::{
        PITH_E_INVALID, PITH_E_REJECTED, PITH_OK, fingerprint_and_serialize,
        pith_video_fingerprint, pith_video_free,
    };

    /// The committed reference fixture, read once.
    fn a_64x48() -> Vec<u8> {
        std::fs::read(format!(
            "{}/tests/fixtures/a_64x48.mp4",
            env!("CARGO_MANIFEST_DIR")
        ))
        .expect("fixture")
    }

    /// A committed conformance fixture, fingerprinted end-to-end
    /// through the raw FFI: status OK, the length matches the
    /// serialization, the header is the documented one, and the buffer
    /// round-trips through `pith_video_free`.
    #[test]
    fn ffi_fingerprint_reproduces_the_canonical_stream() {
        let mp4 = a_64x48();
        let expected = fingerprint_and_serialize(&mp4).expect("decode");

        let mut out: *mut u8 = core::ptr::null_mut();
        let mut out_len: usize = 0;
        let status =
            unsafe { pith_video_fingerprint(mp4.as_ptr(), mp4.len(), &mut out, &mut out_len) };
        assert_eq!(status, PITH_OK);
        assert_eq!(out_len, expected.len());
        let handed_back = unsafe { core::slice::from_raw_parts(out, out_len) };
        assert_eq!(handed_back, expected.as_slice());
        // The 28-byte header is the documented one: 64x48, 8 sampled
        // frames, duration 4.0 s (`0x4010…`), fps 2.0 (`0x4000…`) —
        // every field big-endian.
        assert_eq!(
            &handed_back[..28],
            &[
                0, 0, 0, 64, // width
                0, 0, 0, 48, // height
                0, 0, 0, 8, // sampled_frames
                0x40, 0x10, 0, 0, 0, 0, 0, 0, // duration bits
                0x40, 0, 0, 0, 0, 0, 0, 0, // fps_sampled bits
            ]
        );
        // Stream length: 28-byte header + 8 frame hashes + 128 LE
        // minhash words + 32 raw digest bytes.
        assert_eq!(out_len, 28 + 8 * 8 + 128 * 8 + 32);
        unsafe { pith_video_free(out, out_len) };
    }

    /// Null pointers are [`PITH_E_INVALID`]; garbage input is
    /// [`PITH_E_REJECTED`]; a null buffer is a legal free.
    #[test]
    fn ffi_refusals() {
        let mut out: *mut u8 = core::ptr::null_mut();
        let mut out_len: usize = 0;
        let null_data =
            unsafe { pith_video_fingerprint(core::ptr::null(), 0, &mut out, &mut out_len) };
        assert_eq!(null_data, PITH_E_INVALID);

        let garbage_bytes = [0u8; 16];
        let null_out = unsafe {
            pith_video_fingerprint(
                garbage_bytes.as_ptr(),
                garbage_bytes.len(),
                core::ptr::null_mut(),
                &mut out_len,
            )
        };
        assert_eq!(null_out, PITH_E_INVALID);

        let null_out_len = unsafe {
            pith_video_fingerprint(
                garbage_bytes.as_ptr(),
                garbage_bytes.len(),
                &mut out,
                core::ptr::null_mut(),
            )
        };
        assert_eq!(null_out_len, PITH_E_INVALID);

        let garbage = unsafe {
            pith_video_fingerprint(
                garbage_bytes.as_ptr(),
                garbage_bytes.len(),
                &mut out,
                &mut out_len,
            )
        };
        assert_eq!(garbage, PITH_E_REJECTED);

        // A non-null pointer over zero bytes is readable and decodes
        // far enough to be *rejected* (empty input: InvalidMagic), not
        // invalid.
        let empty =
            unsafe { pith_video_fingerprint(garbage_bytes.as_ptr(), 0, &mut out, &mut out_len) };
        assert_eq!(empty, PITH_E_REJECTED);

        unsafe { pith_video_free(core::ptr::null_mut(), 0) };
    }

    /// The safe core rejects malformed input instead of panicking:
    /// garbage bytes and the empty stream alike.
    #[test]
    fn safe_core_rejects_garbage() {
        assert_eq!(
            fingerprint_and_serialize(&[0xAB; 4096]),
            Err(PITH_E_REJECTED)
        );
        assert_eq!(fingerprint_and_serialize(&[]), Err(PITH_E_REJECTED));
    }
}
