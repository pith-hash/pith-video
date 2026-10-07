package hash.pith;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/** Java bindings for {@code pith-video}: whole-file mp4/mov (H.264)
 * fingerprints over the suite cdylib.
 *
 * <p>{@link #fingerprint(byte[])} returns the <dfn>canonical
 * stream</dfn> every {@code reference.json} vector is defined over
 * (28-byte big-endian header, big-endian frame pHashes,
 * <strong>little-endian</strong> MinHash words, raw 32-byte digest;
 * {@link Fingerprint#parse} unpacks it). Refusals throw
 * {@link PithFfiException}, never crash the JVM.
 *
 * <p>The cdylib is resolved once per process — {@code PITH_CDYLIB}
 * (explicit file), {@code PITH_CDYLIB_DIR} (directory, relative
 * resolves against the working directory and its ancestors), then the
 * {@code target/release} of a repository checkout — and loaded with
 * {@link System#load}.
 */
public final class PithVideo {
    /** Status: success. */
    public static final int PITH_OK = 0;
    /** Status: a caller argument is invalid. */
    public static final int PITH_E_INVALID = -1;
    /** Status: the core decoder refused the input. */
    public static final int PITH_E_REJECTED = -2;

    private static final String CDYLIB = PithNative.findCdylib("pith_video");

    static {
        System.load(CDYLIB);
    }

    private PithVideo() {
    }

    /** Fingerprints a whole ISO-BMFF file (mp4/mov, H.264 video track)
     * into the canonical byte stream.
     *
     * @param input the complete file bytes
     * @return the canonical stream: 28-byte BE header (width, height,
     *         sampled frames, duration bits, fps bits), {@code n}
     *         big-endian frame pHashes, 128 little-endian MinHash
     *         words, the raw 32-byte content digest
     * @throws PithFfiException {@code -1} on a null input array,
     *         {@code -2} when the decoder refuses the input
     *         (malformed container, unsupported/fragmented stream,
     *         limit exceeded) */
    public static native byte[] fingerprint(byte[] input);

    /** The canonical fingerprint stream, unpacked into the fields the
     * {@code reference.json} vectors pin: facts as plain integers,
     * f64s as their raw IEEE-754 bit patterns ({@code durationBits}),
     * and the MinHash fold both as words and as the raw little-endian
     * blob the recorded {@code minhash_fnv1a64}/{@code minhash_sha256}
     * hash. */
    public static final class Fingerprint {
        /** Encoded video width in pixels. */
        public final int width;
        /** Encoded video height in pixels. */
        public final int height;
        /** Number of sampled frames (= {@link #framePhashes}.length). */
        public final int sampledFrames;
        /** {@code duration} seconds as the raw f64 bit pattern. */
        public final long durationBits;
        /** The sampling rate as the raw f64 bit pattern. */
        public final long fpsSampledBits;
        /** Frame pHashes in presentation order, unpacked from BE words. */
        public final long[] framePhashes;
        /** The 128 MinHash words, unpacked from their LE bytes. */
        public final long[] minhashWords;
        /** The raw 1024-byte little-endian MinHash fold blob. */
        public final byte[] minhashLe;
        /** The tier-1 content digest, raw 32 bytes. */
        public final byte[] contentDigest;

        private Fingerprint(int width, int height, int sampledFrames, long durationBits,
                long fpsSampledBits, long[] framePhashes, long[] minhashWords,
                byte[] minhashLe, byte[] contentDigest) {
            this.width = width;
            this.height = height;
            this.sampledFrames = sampledFrames;
            this.durationBits = durationBits;
            this.fpsSampledBits = fpsSampledBits;
            this.framePhashes = framePhashes;
            this.minhashWords = minhashWords;
            this.minhashLe = minhashLe;
            this.contentDigest = contentDigest;
        }

        /** Unpacks the canonical stream; throws {@link IllegalArgumentException}
         * when the length does not match the header. */
        public static Fingerprint parse(byte[] wire) {
            ByteBuffer be = ByteBuffer.wrap(wire).order(ByteOrder.BIG_ENDIAN);
            if (wire.length < 28) {
                throw new IllegalArgumentException("truncated fingerprint header");
            }
            int width = be.getInt(0);
            int height = be.getInt(4);
            int sampledFrames = be.getInt(8);
            long durationBits = be.getLong(12);
            long fpsSampledBits = be.getLong(20);
            int framesOffset = 28;
            int minhashOffset = framesOffset + 8 * sampledFrames;
            int digestOffset = minhashOffset + 1024;
            if (wire.length != digestOffset + 32) {
                throw new IllegalArgumentException("fingerprint length " + wire.length
                        + " does not match " + sampledFrames + " sampled frames");
            }
            long[] frames = new long[sampledFrames];
            for (int i = 0; i < sampledFrames; i++) {
                frames[i] = be.getLong(framesOffset + 8 * i);
            }
            byte[] minhashLe = Arrays.copyOfRange(wire, minhashOffset, digestOffset);
            ByteBuffer le = ByteBuffer.wrap(minhashLe).order(ByteOrder.LITTLE_ENDIAN);
            long[] minhash = new long[128];
            for (int i = 0; i < 128; i++) {
                minhash[i] = le.getLong(8 * i);
            }
            byte[] digest = Arrays.copyOfRange(wire, digestOffset, wire.length);
            return new Fingerprint(width, height, sampledFrames, durationBits,
                    fpsSampledBits, frames, minhash, minhashLe, digest);
        }

        /** The frame pHashes as the {@code frame_phashes_hex} strings
         * (16-digit lowercase hex each). */
        public List<String> framePhashesHex() {
            List<String> hex = new ArrayList<>(framePhashes.length);
            for (long phash : framePhashes) {
                hex.add(hex16(phash));
            }
            return hex;
        }

        /** {@code duration_bits}: the duration as 16-digit hex of the f64 bit pattern. */
        public String durationBitsHex() {
            return hex16(durationBits);
        }

        /** {@code fps_sampled_bits}: the sampling rate as 16-digit hex. */
        public String fpsSampledBitsHex() {
            return hex16(fpsSampledBits);
        }

        /** {@code minhash_word_0}: the first MinHash word as 16-digit hex. */
        public String minhashWord0Hex() {
            return hex16(minhashWords[0]);
        }

        /** {@code minhash_word_1}: the second MinHash word as 16-digit hex. */
        public String minhashWord1Hex() {
            return hex16(minhashWords[1]);
        }

        /** {@code content_digest_sha256}: lowercase hex of the raw digest. */
        public String contentDigestHex() {
            return PithVideo.hex(contentDigest);
        }
    }

    /** Convenience wrapper over {@link Fingerprint#parse(byte[])}. */
    public static Fingerprint parseFingerprint(byte[] wire) {
        return Fingerprint.parse(wire);
    }

    /** The standard FNV-1a 64-bit hash: offset basis
     * {@code 0xcbf29ce484222325}, prime {@code 0x100000001b3} — the
     * algorithm the recorded {@code minhash_fnv1a64} uses over the
     * little-endian word bytes. */
    public static long fnv1a64(byte[] data) {
        long hash = 0xCBF29CE484222325L;
        for (byte b : data) {
            hash = (hash ^ (b & 0xFF)) * 0x100000001B3L;
        }
        return hash;
    }

    static String hex(byte[] bytes) {
        StringBuilder out = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            out.append(Character.forDigit((b >> 4) & 0xF, 16));
            out.append(Character.forDigit(b & 0xF, 16));
        }
        return out.toString();
    }

    static String hex16(long value) {
        return String.format("%016x", value);
    }

    static byte[] unhex(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        }
        return out;
    }

    static long parseHex64(String hex) {
        return Long.parseUnsignedLong(hex, 16);
    }
}
