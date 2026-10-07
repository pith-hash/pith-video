// SPDX-License-Identifier: MIT
// Copyright (c) 2026 pith-hash

// Package pithvideo provides Go bindings for the pith-video Rust cdylib:
// video fingerprinting into the canonical vector stream.
//
// The single Rust core (built by `cargo build --release`) is loaded at
// runtime; the package carries zero module dependencies. On unix the
// cdylib is opened with dlopen through cgo, on Windows with
// LoadLibrary through the standard syscall package — both resolve the
// library through the same discovery chain, so `go build ./... &&
// go test ./...` works unchanged on every OS the CD matrix builds.
//
// Discovery order (the suite's cdylib convention):
//
//  1. PITH_CDYLIB — an explicit cdylib file path;
//  2. PITH_CDYLIB_DIR — a directory scanned for the cdylib names (the
//     CD pipeline points this at target/release);
//  3. <repo root>/target/release — the repository working-tree layout,
//     anchored at this package's source directory, so a source
//     checkout runs against a local cargo build unconfigured.
//
// The FFI surface is one fingerprint operation plus one free:
// pith_video_fingerprint fingerprints a whole ISO-BMFF file (mp4/mov,
// H.264 video track) into the canonical byte stream the reference.json
// vectors are defined over, and pith_video_free releases the
// handed-out buffer.
//
// Canonical stream layout (every multi-byte field big-endian EXCEPT
// the MinHash words, which are little-endian because the pinned
// minhash_fnv1a64 / minhash_sha256 folds hash the little-endian
// form):
//
//	width u32 BE, height u32 BE, sampled_frames u32 BE,
//	duration f64-bits u64 BE, fps_sampled f64-bits u64 BE,
//	sampled_frames × frame pHash u64 BE (presentation order),
//	128 × MinHash word u64 LE,
//	content digest, raw 32 bytes.
package pithvideo

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"unsafe"
)

// Status codes returned by the cdylib's C ABI.
const (
	// StatusOK: success.
	StatusOK int32 = 0
	// StatusInvalid: a caller argument is invalid (a null pointer).
	StatusInvalid int32 = -1
	// StatusRejected: the core decoder refused the input (malformed
	// container or H.264 stream, unsupported codec, fragmented MP4, a
	// limits ceiling exceeded).
	StatusRejected int32 = -2
)

// MinhashWords is the MinHash signature width — part of the wire
// contract.
const MinhashWords = 128

// cdylibNames are the file names cargo may drop into the build
// directory, per platform (windows / linux / macOS).
var cdylibNames = []string{"pith_video.dll", "libpith_video.so", "libpith_video.dylib"}

// FfiError reports a non-zero status code from the cdylib.
type FfiError struct {
	// Op is the FFI operation name.
	Op string
	// Status is the raw status code the FFI returned.
	Status int32
}

func (e *FfiError) Error() string {
	kind := "unknown failure"
	switch e.Status {
	case StatusInvalid:
		kind = "invalid argument"
	case StatusRejected:
		kind = "input rejected"
	}
	return fmt.Sprintf("%s failed: %s (status %d)", e.Op, kind, e.Status)
}

// FindCdylib locates the cdylib through the suite's discovery chain.
func FindCdylib() (string, error) {
	if p := os.Getenv("PITH_CDYLIB"); p != "" {
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
			return filepath.Abs(p)
		}
	}
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("pithvideo: cannot locate the package source directory")
	}
	pkgDir := filepath.Dir(thisFile)
	repoRoot := filepath.Dir(filepath.Dir(pkgDir)) // sdk/go -> sdk -> repo root

	var dirs []string
	if env := os.Getenv("PITH_CDYLIB_DIR"); env != "" {
		dirs = append(dirs, env)
		if !filepath.IsAbs(env) {
			dirs = append(dirs, filepath.Join(repoRoot, env))
		}
	}
	dirs = append(dirs, filepath.Join(repoRoot, "target", "release"))
	for _, dir := range dirs {
		for _, name := range cdylibNames {
			p := filepath.Join(dir, name)
			if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
				return p, nil
			}
		}
	}
	return "", fmt.Errorf(
		"pithvideo: no cdylib found (searched PITH_CDYLIB, PITH_CDYLIB_DIR and <repo>/target/release); run `cargo build --release` first",
	)
}

// locate resolves the cdylib path once per process.
var locate = sync.OnceValues(FindCdylib)

// hex16 renders one u64 as the 16-digit lowercase hex reference.json pins.
func hex16(v uint64) string {
	return fmt.Sprintf("%016x", v)
}

// Fingerprint is one decoded video fingerprint, re-expressed from the
// canonical byte stream. The *Bits / *Hex fields are the lowercase
// hex strings reference.json pins, so comparisons are plain string
// equality.
type Fingerprint struct {
	// Width is the displayed width of the decoded stream.
	Width uint32
	// Height is the displayed height.
	Height uint32
	// SampledFrames is the number of sampled (2 fps) frames.
	SampledFrames uint32
	// DurationBits is the track duration as the 16-hex-digit IEEE-754
	// bit pattern.
	DurationBits string
	// FpsSampledBits is the achieved sampling rate as the 16-hex-digit
	// bit pattern.
	FpsSampledBits string
	// FramePhashesHex lists the frame pHashes in presentation order as
	// 16-hex-digit strings.
	FramePhashesHex []string
	// MinhashWord0 is the first MinHash word as a 16-hex-digit string.
	MinhashWord0 string
	// MinhashWord1 is the second MinHash word as a 16-hex-digit string.
	MinhashWord1 string
	// MinhashLE is the 128 MinHash words little-endian (1024 bytes) —
	// the blob the pinned FNV-1a 64 / SHA-256 folds hash.
	MinhashLE []byte
	// ContentDigestHex is the tier-1 content digest, lowercase hex.
	ContentDigestHex string
	// Raw is the canonical byte stream itself.
	Raw []byte
}

// FingerprintVideo fingerprints a complete ISO-BMFF file (mp4/mov,
// H.264 video track) into the canonical byte stream the reference.json
// vectors are defined over. The returned slice is a Go copy; the
// handed-out cdylib buffer is released before returning.
func FingerprintVideo(data []byte) ([]byte, error) {
	libPath, err := locate()
	if err != nil {
		return nil, err
	}
	var out *byte
	var outLen uintptr
	var dataPtr *byte
	if len(data) > 0 {
		dataPtr = &data[0]
	}
	status, err := ffiFingerprint(libPath, dataPtr, len(data), &out, &outLen)
	if err != nil {
		return nil, err
	}
	if status != StatusOK {
		return nil, &FfiError{Op: "pith_video_fingerprint", Status: status}
	}
	buf := make([]byte, outLen)
	copy(buf, unsafe.Slice(out, outLen))
	ffiFree(libPath, out, outLen)
	return buf, nil
}

// ParseFingerprint re-expresses the canonical byte stream as a
// Fingerprint.
func ParseFingerprint(raw []byte) (Fingerprint, error) {
	const headerLen = 28
	if len(raw) < headerLen+MinhashWords*8+32 {
		return Fingerprint{}, fmt.Errorf("pithvideo: canonical stream is shorter than the 28-byte header, 128 minhash words and the 32-byte digest")
	}
	sampledFrames := binary.BigEndian.Uint32(raw[8:12])
	base := headerLen + int(sampledFrames)*8
	if len(raw) < base+MinhashWords*8+32 {
		return Fingerprint{}, fmt.Errorf("pithvideo: canonical stream is shorter than its own frame table")
	}
	phashes := make([]string, sampledFrames)
	for i := range phashes {
		phashes[i] = hex16(binary.BigEndian.Uint64(raw[headerLen+i*8:]))
	}
	le := raw[base : base+MinhashWords*8]
	return Fingerprint{
		Width:            binary.BigEndian.Uint32(raw[0:4]),
		Height:           binary.BigEndian.Uint32(raw[4:8]),
		SampledFrames:    sampledFrames,
		DurationBits:     hex.EncodeToString(raw[12:20]),
		FpsSampledBits:   hex.EncodeToString(raw[20:28]),
		FramePhashesHex:  phashes,
		MinhashWord0:     hex16(binary.LittleEndian.Uint64(le[0:8])),
		MinhashWord1:     hex16(binary.LittleEndian.Uint64(le[8:16])),
		MinhashLE:        le,
		ContentDigestHex: hex.EncodeToString(raw[base+MinhashWords*8:]),
		Raw:              raw,
	}, nil
}
