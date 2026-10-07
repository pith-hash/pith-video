package hash.pith;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;

/** Hex-exact conformance: the committed reference vectors through the
 * real JVM and the suite cdylib.
 *
 * <p>Every vector in the repository-root {@code reference.json} is
 * replayed through {@link PithVideo#fingerprint(byte[])} and compared
 * against every recorded field. The 9 pinned vectors compare the
 * frame pHash chain, the MinHash fold (word 0/1 plus FNV-1a 64 and
 * SHA-256 recomputed over the little-endian word bytes) and the
 * content digest hex-exact; the 2 stability-excluded solid-color
 * vectors compare only the platform-independent fields. Every
 * recorded decode error kind comes back as {@link PithFfiException},
 * never a crash.
 */
class ReferenceVectorsTest {
    private static final Path REPO_ROOT = PithNative.repoRoot();
    private static final JsonObject REFERENCE = reference();
    private static final Map<String, JsonObject> VECTORS = vectors();

    private static JsonObject reference() {
        try {
            return JsonParser.parseString(
                    Files.readString(REPO_ROOT.resolve("reference.json")))
                    .getAsJsonObject();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static Map<String, JsonObject> vectors() {
        Map<String, JsonObject> out = new LinkedHashMap<>();
        for (JsonElement element : REFERENCE.getAsJsonArray("vectors")) {
            JsonObject vector = element.getAsJsonObject();
            out.put(vector.get("name").getAsString(), vector);
        }
        return out;
    }

    private static byte[] fixture(String relative) {
        try {
            return Files.readAllBytes(REPO_ROOT.resolve(relative));
        } catch (Exception e) {
            throw new IllegalStateException(relative, e);
        }
    }

    private static String sha256Hex(byte[] data) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(data);
            return PithVideo.hex(digest);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @Test
    void cdylibIsDiscoverable() {
        assertTrue(Files.isRegularFile(Path.of(PithNative.findCdylib("pith_video"))));
    }

    @Test
    void referenceVectorsReproduceHexExact() {
        for (String name : new TreeSet<>(VECTORS.keySet())) {
            JsonObject vector = VECTORS.get(name);
            byte[] data = fixture(vector.get("input_path").getAsString());
            byte[] raw = PithVideo.fingerprint(data);
            PithVideo.Fingerprint fingerprint = PithVideo.parseFingerprint(raw);

            // Platform-independent facts, pinned for every vector.
            assertEquals(vector.get("width").getAsInt(), fingerprint.width, name);
            assertEquals(vector.get("height").getAsInt(), fingerprint.height, name);
            assertEquals(vector.get("sampled_frames").getAsInt(), fingerprint.sampledFrames, name);
            assertEquals(vector.get("duration_bits").getAsString(),
                    fingerprint.durationBitsHex(), name);
            assertEquals(vector.get("fps_sampled_bits").getAsString(),
                    fingerprint.fpsSampledBitsHex(), name);
            assertEquals(vector.get("content_digest_sha256").getAsString(),
                    fingerprint.contentDigestHex(), name);

            if (!vector.get("phash_hex_pinned").getAsBoolean()) {
                // Stability-excluded solid-color source: the pHash bits
                // and the MinHash fold over them sit at the DCT subnormal
                // noise floor (libm-sensitive); only the fields above are
                // a cross-platform contract.
                continue;
            }

            List<String> expected = new java.util.ArrayList<>();
            for (JsonElement phash : vector.getAsJsonArray("frame_phashes_hex")) {
                expected.add(phash.getAsString());
            }
            assertEquals(expected, fingerprint.framePhashesHex(), name);
            assertEquals(vector.get("minhash_word_0").getAsString(),
                    fingerprint.minhashWord0Hex(), name);
            assertEquals(vector.get("minhash_word_1").getAsString(),
                    fingerprint.minhashWord1Hex(), name);
            // The folds hash the LITTLE-ENDIAN word bytes — recomputed
            // here with the standard algorithms, not trusted from the
            // cdylib.
            assertEquals(vector.get("minhash_fnv1a64").getAsString(),
                    PithVideo.hex16(PithVideo.fnv1a64(fingerprint.minhashLe)), name);
            assertEquals(vector.get("minhash_sha256").getAsString(),
                    sha256Hex(fingerprint.minhashLe), name);
        }
    }

    @Test
    void decodeErrorsRefuseInsteadOfCrashing() {
        for (JsonElement element : REFERENCE.getAsJsonArray("errors")) {
            JsonObject error = element.getAsJsonObject();
            byte[] data;
            if ("inline-hex".equals(error.get("input_kind").getAsString())) {
                data = PithVideo.unhex(error.get("input_hex").getAsString());
            } else {
                data = fixture(error.get("input_path").getAsString());
            }
            PithFfiException thrown = assertThrows(PithFfiException.class,
                    () -> PithVideo.fingerprint(data), error.get("name").getAsString());
            if (data.length > 0) {
                // Non-empty refusals reach the decoder and come back rejected.
                assertEquals(PithVideo.PITH_E_REJECTED, thrown.getStatus(),
                        error.get("name").getAsString());
            }
            // A zero-length buffer may surface as either refusal code;
            // the contract is a status code, never a crash.
        }
    }

    @Test
    void fullStreamMatchesRustPinnedValue() {
        // a_64x48.mp4's facts, pinned in the committed reference.json
        // and re-derived by the Rust unit tests; this test fails loudly
        // even if reference.json were regenerated wrongly.
        byte[] data = fixture("tests/fixtures/a_64x48.mp4");
        PithVideo.Fingerprint fingerprint =
                PithVideo.parseFingerprint(PithVideo.fingerprint(data));
        assertEquals("4010000000000000", fingerprint.durationBitsHex()); // 4.0 s
        assertEquals("4000000000000000", fingerprint.fpsSampledBitsHex()); // 2.0 fps
        assertEquals("ac798c7786266e8c", fingerprint.framePhashesHex().get(0));
        assertEquals("2a9354939727ac5d", fingerprint.minhashWord0Hex());
        assertEquals("72a4bbfd76647b2dc9ee06d8d6975ae73ff1ba2e789877dbc3ca88e37fc718aa",
                fingerprint.contentDigestHex());
        // Big-endian header spot-check: 64x48, 8 sampled frames.
        assertArrayEquals(new byte[] {0, 0, 0, 64, 0, 0, 0, 48, 0, 0, 0, 8},
                java.util.Arrays.copyOfRange(PithVideo.fingerprint(data), 0, 12));
    }
}
