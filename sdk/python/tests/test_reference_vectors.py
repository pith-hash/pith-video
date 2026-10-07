# SPDX-License-Identifier: MIT
# Copyright (c) 2026 pith-hash
"""Hex-exact conformance: the committed reference vectors through ctypes.

Every vector in the repository-root ``reference.json`` is replayed
through the cdylib. The 9 pinned vectors compare every pinned field
hex-exact — frame pHash chain, MinHash fold (word 0/1, FNV-1a 64 and
SHA-256 over the little-endian word bytes) and the content digest.
The 2 stability-excluded solid-color vectors (``short_32x24.mp4``,
``tiny_16x16.mp4``) compare only the platform-independent fields —
their pHash bits and the MinHash fold over them sit at the DCT
subnormal noise floor and are libm-sensitive, so they are never
compared cross-platform. Every recorded decode error kind comes back
as ``FfiError``, never a crash.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from pith_video import FfiError, find_cdylib, fingerprint, parse_fingerprint

REPO_ROOT = Path(__file__).resolve().parents[3]
REFERENCE = json.loads((REPO_ROOT / "reference.json").read_text(encoding="utf-8"))
VECTORS = {v["name"]: v for v in REFERENCE["vectors"]}


def fnv1a64(data: bytes) -> int:
    """The standard FNV-1a 64 the minhash fold is pinned with."""
    h = 0xCBF29CE484222325
    for b in data:
        h = ((h ^ b) * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h


def test_cdylib_is_discoverable() -> None:
    path = find_cdylib()
    assert path.is_file(), path


@pytest.mark.parametrize("name", sorted(VECTORS))
def test_reference_vector(name: str) -> None:
    vector = VECTORS[name]
    data = (REPO_ROOT / vector["input_path"]).read_bytes()

    raw = fingerprint(data)
    fp = parse_fingerprint(raw)
    # Platform-independent facts, pinned for every vector.
    assert fp.width == vector["width"], name
    assert fp.height == vector["height"], name
    assert fp.sampled_frames == vector["sampled_frames"], name
    assert fp.duration_bits == vector["duration_bits"], name
    assert fp.fps_sampled_bits == vector["fps_sampled_bits"], name
    assert fp.content_digest_hex == vector["content_digest_sha256"], name

    if not vector["phash_hex_pinned"]:
        # Stability-excluded solid-color source: the pHash bits and the
        # MinHash fold over them sit at the DCT subnormal noise floor
        # (libm-sensitive); only the fields above are a cross-platform
        # contract.
        return

    assert list(fp.frame_phashes_hex) == vector["frame_phashes_hex"], name
    assert fp.minhash_word_0 == vector["minhash_word_0"], name
    assert fp.minhash_word_1 == vector["minhash_word_1"], name
    # The folds hash the LITTLE-ENDIAN word bytes — recomputed here
    # with the standard algorithms, not trusted from the cdylib.
    assert format(fnv1a64(fp.minhash_le), "016x") == vector["minhash_fnv1a64"], name
    assert hashlib.sha256(fp.minhash_le).hexdigest() == vector["minhash_sha256"], name


@pytest.mark.parametrize("error", REFERENCE["errors"], ids=lambda e: e["name"])
def test_decode_error_is_refused_not_crashing(error) -> None:
    if error["input_kind"] == "inline-hex":
        data = bytes.fromhex(error["input_hex"])
    else:
        data = (REPO_ROOT / error["input_path"]).read_bytes()
    with pytest.raises(FfiError) as err:
        fingerprint(data)
    if data:
        # Non-empty refusals reach the decoder and come back rejected.
        assert err.value.status == -2, error["name"]
    # A zero-length buffer may surface as either refusal depending on
    # whether the binding hands the cdylib a null pointer; the
    # contract is a status code, never a crash.


def test_full_stream_matches_a_rust_pinned_value() -> None:
    # a_64x48.mp4's facts, pinned in the committed reference.json and
    # re-derived by the Rust unit tests; this test fails loudly even if
    # reference.json were regenerated wrongly.
    data = (REPO_ROOT / "tests" / "fixtures" / "a_64x48.mp4").read_bytes()
    raw = fingerprint(data)
    fp = parse_fingerprint(raw)
    assert fp.duration_bits == "4010000000000000"  # 4.0 s
    assert fp.fps_sampled_bits == "4000000000000000"  # 2.0 fps
    assert fp.frame_phashes_hex[0] == "ac798c7786266e8c"
    assert fp.minhash_word_0 == "2a9354939727ac5d"
    assert (
        fp.content_digest_hex
        == "72a4bbfd76647b2dc9ee06d8d6975ae73ff1ba2e789877dbc3ca88e37fc718aa"
    )
    # Big-endian header spot-check: 64x48, 8 sampled frames.
    assert raw[:12] == bytes([0, 0, 0, 64, 0, 0, 0, 48, 0, 0, 0, 8])
