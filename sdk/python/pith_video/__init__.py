# SPDX-License-Identifier: MIT
# Copyright (c) 2026 pith-hash
"""pith-video SDK: video fingerprinting through ctypes.

The single Rust core (the ``pith-video`` cdylib built by
``cargo build --release``) is loaded at runtime; this package carries
no third-party dependency — ``ctypes`` is the standard library.

Discovery order (the suite's cdylib convention):

1. ``PITH_CDYLIB`` — an explicit cdylib *file* path;
2. ``PITH_CDYLIB_DIR`` — a *directory* scanned for the cdylib names
   (the CD pipeline points this at ``target/release``);
3. the package directory itself (the built wheel ships the cdylib as
   package data);
4. ``<repo root>/target/release`` — the repository working-tree layout,
   so a source checkout runs against a local cargo build with no
   configuration.

The FFI surface is one fingerprint operation plus one free:
``pith_video_fingerprint`` fingerprints a whole ISO-BMFF file
(mp4/mov, H.264 video track) into the canonical byte stream the
``reference.json`` vectors are defined over, and ``pith_video_free``
releases the handed-out buffer.

Canonical stream layout (every multi-byte field big-endian EXCEPT the
MinHash words, which are little-endian because the pinned
``minhash_fnv1a64`` / ``minhash_sha256`` folds hash the little-endian
form):

1. ``width`` as ``u32`` BE, ``height`` as ``u32`` BE,
   ``sampled_frames`` as ``u32`` BE;
2. ``duration`` and ``fps_sampled`` as IEEE-754 bit patterns,
   ``u64`` BE each;
3. ``sampled_frames`` frame pHashes, ``u64`` BE each, presentation
   order;
4. exactly 128 MinHash words, ``u64`` little-endian each;
5. the raw 32-byte content digest.
"""

from __future__ import annotations

import ctypes
import os
from dataclasses import dataclass
from pathlib import Path

__all__ = [
    "VideoFingerprint",
    "FfiError",
    "LibraryNotFoundError",
    "find_cdylib",
    "fingerprint",
    "parse_fingerprint",
    "MINHASH_WORDS",
    "STATUS_OK",
    "STATUS_INVALID",
    "STATUS_REJECTED",
]

#: Status: success.
STATUS_OK = 0
#: Status: a caller argument is invalid (a null pointer).
STATUS_INVALID = -1
#: Status: the core decoder refused the input (malformed container or
#: H.264 stream, unsupported codec, fragmented MP4, a limits ceiling
#: exceeded).
STATUS_REJECTED = -2

#: The MinHash signature width — part of the wire contract.
MINHASH_WORDS = 128

#: Every cdylib file name cargo may drop into the build directory, per
#: platform (windows / linux / macOS).
CDYLIB_NAMES = ("pith_video.dll", "libpith_video.so", "libpith_video.dylib")


@dataclass(frozen=True)
class VideoFingerprint:
    """One decoded video fingerprint, re-expressed from the canonical
    byte stream.

    The ``*_bits`` / ``*_hex`` fields are the 16-hex-digit (or 64-hex)
    lowercase strings ``reference.json`` pins, so SDK-side comparisons
    are plain string equality. ``minhash_le`` is the 1024
    little-endian word bytes the pinned ``minhash_fnv1a64`` /
    ``minhash_sha256`` folds hash.
    """

    #: Displayed width of the decoded stream.
    width: int
    #: Displayed height.
    height: int
    #: Number of sampled (2 fps) frames.
    sampled_frames: int
    #: Track duration as the 16-hex-digit IEEE-754 bit pattern.
    duration_bits: str
    #: Achieved sampling rate as the 16-hex-digit bit pattern.
    fps_sampled_bits: str
    #: Frame pHashes, presentation order, as 16-hex-digit strings.
    frame_phashes_hex: tuple[str, ...]
    #: First MinHash word as a 16-hex-digit string.
    minhash_word_0: str
    #: Second MinHash word as a 16-hex-digit string.
    minhash_word_1: str
    #: The 128 MinHash words little-endian (1024 bytes) — the blob the
    #: pinned FNV-1a 64 and SHA-256 folds hash.
    minhash_le: bytes
    #: The tier-1 content digest, lowercase hex.
    content_digest_hex: str
    #: The canonical byte stream itself.
    raw: bytes


class LibraryNotFoundError(OSError):
    """No cdylib was found through the discovery chain."""


class FfiError(Exception):
    """A non-zero status code came back from the cdylib."""

    def __init__(self, op: str, status: int) -> None:
        kind = {
            STATUS_INVALID: "invalid argument",
            STATUS_REJECTED: "input rejected",
        }.get(status, "unknown failure")
        super().__init__(f"{op} failed: {kind} (status {status})")
        #: The raw status code the FFI returned.
        self.status = status


def find_cdylib() -> Path:
    """Locates the cdylib through the suite's discovery chain."""
    explicit = os.environ.get("PITH_CDYLIB")
    if explicit:
        p = Path(explicit)
        if p.is_file():
            return p
    env_dir = os.environ.get("PITH_CDYLIB_DIR")
    candidates: list[Path] = []
    if env_dir:
        env_dir_path = Path(env_dir)
        candidates.append(env_dir_path)
        if not env_dir_path.is_absolute():
            # CD and local runs invoke tools from the repository root or
            # from sdk/<lang>; resolve the env value against both.
            candidates.append(Path.cwd() / env_dir_path)
            candidates.append(Path(__file__).resolve().parents[3] / env_dir_path)
    candidates.append(Path(__file__).resolve().parent)  # packaged wheel
    candidates.append(Path(__file__).resolve().parents[3] / "target" / "release")
    for directory in candidates:
        for name in CDYLIB_NAMES:
            p = directory / name
            if p.is_file():
                return p
    raise LibraryNotFoundError(
        "no pith-video cdylib found (searched PITH_CDYLIB, PITH_CDYLIB_DIR, "
        "the package directory and <repo>/target/release); "
        "run `cargo build --release` first"
    )


_lib: ctypes.CDLL | None = None


def _load() -> ctypes.CDLL:
    global _lib
    if _lib is None:
        lib = ctypes.CDLL(str(find_cdylib()))
        lib.pith_video_fingerprint.argtypes = [
            ctypes.c_void_p,  # data
            ctypes.c_size_t,  # len
            ctypes.POINTER(ctypes.c_void_p),  # out buffer
            ctypes.POINTER(ctypes.c_size_t),  # out length
        ]
        lib.pith_video_fingerprint.restype = ctypes.c_int32
        lib.pith_video_free.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        lib.pith_video_free.restype = None
        _lib = lib
    return _lib


def fingerprint(data: bytes) -> bytes:
    """Fingerprints a complete ISO-BMFF file (mp4/mov, H.264 video
    track) into the canonical byte stream the ``reference.json``
    vectors are defined over (see the module docs for the layout).

    Raises :class:`FfiError` with ``status == STATUS_REJECTED`` for any
    refusing input — malformed container or H.264 stream, unsupported
    codec, fragmented MP4 or an exceeded limit; the decoder never
    panics through this boundary.
    """
    out = ctypes.c_void_p()
    out_len = ctypes.c_size_t()
    status = _load().pith_video_fingerprint(data, len(data), ctypes.byref(out), ctypes.byref(out_len))
    if status != STATUS_OK:
        raise FfiError("pith_video_fingerprint", status)
    try:
        return ctypes.string_at(out, out_len.value)
    finally:
        _load().pith_video_free(out, out_len.value)


def parse_fingerprint(raw: bytes) -> VideoFingerprint:
    """Re-expresses the canonical byte stream as a
    :class:`VideoFingerprint`."""
    header = 28
    if len(raw) < header + MINHASH_WORDS * 8 + 32:
        raise ValueError(
            "canonical stream is shorter than the 28-byte header, "
            "128 minhash words and the 32-byte digest"
        )
    width = int.from_bytes(raw[0:4], "big")
    height = int.from_bytes(raw[4:8], "big")
    sampled_frames = int.from_bytes(raw[8:12], "big")
    base = header + 8 * sampled_frames
    if len(raw) < base + MINHASH_WORDS * 8 + 32:
        raise ValueError("canonical stream is shorter than its own frame table")
    minhash_le = raw[base : base + MINHASH_WORDS * 8]
    return VideoFingerprint(
        width=width,
        height=height,
        sampled_frames=sampled_frames,
        duration_bits=raw[12:20].hex(),
        fps_sampled_bits=raw[20:28].hex(),
        frame_phashes_hex=tuple(
            raw[header + 8 * i : header + 8 * i + 8].hex() for i in range(sampled_frames)
        ),
        minhash_word_0=format(int.from_bytes(minhash_le[0:8], "little"), "016x"),
        minhash_word_1=format(int.from_bytes(minhash_le[8:16], "little"), "016x"),
        minhash_le=minhash_le,
        content_digest_hex=raw[base + MINHASH_WORDS * 8 :].hex(),
        raw=raw,
    )
