// SPDX-License-Identifier: MIT
// Copyright (c) 2026 pith-hash

package pithvideo

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// repoRoot resolves the repository root relative to this package
// (sdk/go -> sdk -> repo root), the anchor for reference.json and the
// committed fixtures.
func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(filepath.Join(root, "reference.json")); err != nil || st.IsDir() {
		t.Fatalf("reference.json not found at %s", root)
	}
	return root
}

// vectorJSON mirrors the fields of one reference.json fingerprint
// vector the Go suite checks. The MinHash fold fields are pointers:
// they are null for the stability-excluded solid-color vectors.
type vectorJSON struct {
	Name             string   `json:"name"`
	InputPath        string   `json:"input_path"`
	Width            uint32   `json:"width"`
	Height           uint32   `json:"height"`
	SampledFrames    uint32   `json:"sampled_frames"`
	PhashHexPinned   bool     `json:"phash_hex_pinned"`
	FramePhashesHex  []string `json:"frame_phashes_hex"`
	MinhashWord0     *string  `json:"minhash_word_0"`
	MinhashWord1     *string  `json:"minhash_word_1"`
	MinhashFnv1a64   *string  `json:"minhash_fnv1a64"`
	MinhashSha256    *string  `json:"minhash_sha256"`
	ContentDigestSha string   `json:"content_digest_sha256"`
	DurationBits     string   `json:"duration_bits"`
	FpsSampledBits   string   `json:"fps_sampled_bits"`
}

// errorJSON mirrors one reference.json decode-error entry.
type errorJSON struct {
	Name      string `json:"name"`
	InputKind string `json:"input_kind"`
	InputPath string `json:"input_path"`
	InputHex  string `json:"input_hex"`
}

// reference parses the committed reference.json.
func reference(t *testing.T) ([]vectorJSON, []errorJSON) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "reference.json"))
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Vectors []vectorJSON `json:"vectors"`
		Errors  []errorJSON  `json:"errors"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	return parsed.Vectors, parsed.Errors
}

// fnv1a64 computes the standard FNV-1a 64 the minhash fold is pinned
// with — recomputed here, not trusted from the cdylib.
func fnv1a64(data []byte) uint64 {
	h := uint64(0xcbf29ce484222325)
	for _, b := range data {
		h ^= uint64(b)
		h *= 0x100000001b3
	}
	return h
}

// TestReferenceVectors replays every committed reference.json vector
// through the cdylib. The 9 pinned vectors compare every pinned field
// hex-exact; the 2 stability-excluded solid-color vectors
// (short_32x24.mp4, tiny_16x16.mp4) compare only the
// platform-independent fields — their pHash bits and the MinHash fold
// over them sit at the DCT subnormal noise floor and are
// libm-sensitive, so they are never compared cross-platform.
func TestReferenceVectors(t *testing.T) {
	vectors, _ := reference(t)
	for _, want := range vectors {
		t.Run(want.Name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(repoRoot(t), want.InputPath))
			if err != nil {
				t.Fatal(err)
			}
			raw, err := FingerprintVideo(data)
			if err != nil {
				t.Fatalf("FingerprintVideo(%s): %v", want.Name, err)
			}
			fp, err := ParseFingerprint(raw)
			if err != nil {
				t.Fatal(err)
			}
			if fp.Width != want.Width || fp.Height != want.Height {
				t.Errorf("%s: dims %dx%d, want %dx%d", want.Name, fp.Width, fp.Height, want.Width, want.Height)
			}
			if fp.SampledFrames != want.SampledFrames {
				t.Errorf("%s: sampled frames %d, want %d", want.Name, fp.SampledFrames, want.SampledFrames)
			}
			if fp.DurationBits != want.DurationBits {
				t.Errorf("%s: duration bits %s, want %s", want.Name, fp.DurationBits, want.DurationBits)
			}
			if fp.FpsSampledBits != want.FpsSampledBits {
				t.Errorf("%s: fps bits %s, want %s", want.Name, fp.FpsSampledBits, want.FpsSampledBits)
			}
			if fp.ContentDigestHex != want.ContentDigestSha {
				t.Errorf("%s: content digest %s, want %s", want.Name, fp.ContentDigestHex, want.ContentDigestSha)
			}
			if !want.PhashHexPinned {
				// Stability-excluded solid-color source: the fields
				// above are the whole cross-platform contract.
				return
			}
			if len(fp.FramePhashesHex) != len(want.FramePhashesHex) {
				t.Fatalf("%s: %d frame hashes, want %d", want.Name, len(fp.FramePhashesHex), len(want.FramePhashesHex))
			}
			for i, got := range fp.FramePhashesHex {
				if got != want.FramePhashesHex[i] {
					t.Errorf("%s: frame phash %d = %s, want %s", want.Name, i, got, want.FramePhashesHex[i])
				}
			}
			if fp.MinhashWord0 != *want.MinhashWord0 {
				t.Errorf("%s: minhash word 0 %s, want %s", want.Name, fp.MinhashWord0, *want.MinhashWord0)
			}
			if fp.MinhashWord1 != *want.MinhashWord1 {
				t.Errorf("%s: minhash word 1 %s, want %s", want.Name, fp.MinhashWord1, *want.MinhashWord1)
			}
			if got := fmt.Sprintf("%016x", fnv1a64(fp.MinhashLE)); got != *want.MinhashFnv1a64 {
				t.Errorf("%s: minhash fnv1a64 %s, want %s", want.Name, got, *want.MinhashFnv1a64)
			}
			sum := sha256.Sum256(fp.MinhashLE)
			if got := hex.EncodeToString(sum[:]); got != *want.MinhashSha256 {
				t.Errorf("%s: minhash sha256 %s, want %s", want.Name, got, *want.MinhashSha256)
			}
		})
	}
}

// TestAPinnedFacts pins a_64x48.mp4's facts the Rust unit tests
// re-derive, so the binding fails loudly even if reference.json were
// regenerated wrongly.
func TestAPinnedFacts(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repoRoot(t), "tests", "fixtures", "a_64x48.mp4"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := FingerprintVideo(data)
	if err != nil {
		t.Fatal(err)
	}
	fp, err := ParseFingerprint(raw)
	if err != nil {
		t.Fatal(err)
	}
	if fp.DurationBits != "4010000000000000" { // 4.0 s
		t.Errorf("duration bits %s, want 4010000000000000", fp.DurationBits)
	}
	if fp.FpsSampledBits != "4000000000000000" { // 2.0 fps
		t.Errorf("fps bits %s, want 4000000000000000", fp.FpsSampledBits)
	}
	if len(fp.FramePhashesHex) == 0 || fp.FramePhashesHex[0] != "ac798c7786266e8c" {
		t.Errorf("first frame phash %v, want ac798c7786266e8c", fp.FramePhashesHex)
	}
	if fp.MinhashWord0 != "2a9354939727ac5d" {
		t.Errorf("minhash word 0 %s, want 2a9354939727ac5d", fp.MinhashWord0)
	}
	const wantDigest = "72a4bbfd76647b2dc9ee06d8d6975ae73ff1ba2e789877dbc3ca88e37fc718aa"
	if fp.ContentDigestHex != wantDigest {
		t.Errorf("content digest %s, want %s", fp.ContentDigestHex, wantDigest)
	}
	// Big-endian header spot-check: 64x48, 8 sampled frames.
	wantHeader := []byte{0, 0, 0, 64, 0, 0, 0, 48, 0, 0, 0, 8}
	for i, b := range wantHeader {
		if raw[i] != b {
			t.Fatalf("header byte %d = %d, want %d", i, raw[i], b)
		}
	}
}

// TestDecodeErrorsAreRefused checks the refusal path for every
// recorded error kind: a status code, never a crash. Non-empty inputs
// reach the decoder and come back StatusRejected; a zero-length
// buffer may surface as either refusal (some bindings hand the cdylib
// a null pointer) — the contract is a status code, never a crash.
func TestDecodeErrorsAreRefused(t *testing.T) {
	_, errorList := reference(t)
	for _, e := range errorList {
		t.Run(e.Name, func(t *testing.T) {
			var data []byte
			if e.InputKind == "inline-hex" {
				decoded, err := hex.DecodeString(e.InputHex)
				if err != nil {
					t.Fatal(err)
				}
				data = decoded
			} else {
				read, err := os.ReadFile(filepath.Join(repoRoot(t), e.InputPath))
				if err != nil {
					t.Fatal(err)
				}
				data = read
			}
			_, err := FingerprintVideo(data)
			if err == nil {
				t.Fatalf("%s: decode unexpectedly succeeded", e.Name)
			}
			ffi, ok := err.(*FfiError)
			if !ok {
				t.Fatalf("%s: want FfiError, got %v", e.Name, err)
			}
			if len(data) > 0 && ffi.Status != StatusRejected {
				t.Errorf("%s: want StatusRejected, got %d", e.Name, ffi.Status)
			}
		})
	}
}
