package hash.pith;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/** Locates and loads the suite cdylib for the JNI bindings.
 *
 * <p>The discovery chain mirrors the suite's Python/Node/Go SDKs:
 * <ol>
 *   <li>{@code PITH_CDYLIB} — an explicit cdylib file path;</li>
 *   <li>{@code PITH_CDYLIB_DIR} — a directory holding the platform
 *       cdylib name ({@code pith_video.dll}, {@code libpith_video.so}
 *       or {@code libpith_video.dylib}); relative values are resolved
 *       against the working directory and its ancestors;</li>
 *   <li>the native library bundled in this JAR under
 *       {@code hash/pith/native/<platform>/}, extracted to a private temp
 *       directory;</li>
 *   <li>the {@code target/release} directory of the working directory
 *       or one of its ancestors (a plain repository checkout).</li>
 * </ol>
 */
final class PithNative {
    private PithNative() {
    }

    private static final String RESOURCE_ROOT = "/hash/pith/native/";

    /** Node-style platform id, e.g. {@code linux-x64}; the same ids the npm prebuilds use. */
    static String platformId(String osName, String osArch) {
        String os = osName.toLowerCase(Locale.ROOT);
        String arch = osArch.toLowerCase(Locale.ROOT);
        String normOs = os.contains("win") ? "win32"
                : (os.contains("mac") || os.contains("darwin")) ? "darwin"
                : os.contains("linux") ? "linux" : null;
        String normArch = (arch.equals("amd64") || arch.equals("x86_64")) ? "x64"
                : (arch.equals("aarch64") || arch.equals("arm64")) ? "arm64" : null;
        if (normOs == null || normArch == null) {
            throw new PithLibraryNotFoundException(
                    "unsupported platform " + os.replace(' ', '_') + "-" + arch
                            + " (bundled natives: linux-x64, linux-arm64, darwin-arm64, darwin-x64, win32-x64)");
        }
        return normOs + "-" + normArch;
    }

    /**
     * Copies the bundled native for {@code platformId} into a fresh owner-only temp
     * directory and returns the absolute file path, or {@code null} when the JAR
     * carries no such resource. A fresh directory per call keeps two JVMs from
     * racing on one file and keeps other users from pre-creating the target.
     */
    static String extractBundled(String platformId, String fileName) {
        String resource = RESOURCE_ROOT + platformId + "/" + fileName;
        try (InputStream in = PithNative.class.getResourceAsStream(resource)) {
            if (in == null) {
                return null;
            }
            Path dir = Files.createTempDirectory("pith-native-");
            try {
                Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwx------"));
            } catch (UnsupportedOperationException ignored) {
                // Windows: the per-user temp directory is already private.
            }
            Path file = dir.resolve(fileName);
            Files.copy(in, file, StandardCopyOption.REPLACE_EXISTING);
            file.toFile().deleteOnExit();
            dir.toFile().deleteOnExit();
            return file.toAbsolutePath().toString();
        } catch (java.io.IOException e) {
            throw new PithLibraryNotFoundException("could not extract bundled native " + resource + ": " + e);
        }
    }

    /** Resolves the cdylib path and returns it in {@link System#load}-ready form. */
    static String findCdylib(String stem) {
        String name = cdylibName(stem);
        String explicit = System.getenv("PITH_CDYLIB");
        if (explicit != null && !explicit.isBlank()) {
            Path file = Paths.get(explicit);
            if (!Files.isRegularFile(file)) {
                throw new PithLibraryNotFoundException(
                        "PITH_CDYLIB does not name a file: " + file.toAbsolutePath());
            }
            return file.toAbsolutePath().toString();
        }
        String dir = System.getenv("PITH_CDYLIB_DIR");
        if (dir != null && !dir.isBlank()) {
            Path directory = Paths.get(dir);
            for (Path base : searchRoots()) {
                Path candidate = base.resolve(directory).resolve(name);
                if (Files.isRegularFile(candidate)) {
                    return candidate.toAbsolutePath().toString();
                }
            }
            throw new PithLibraryNotFoundException(
                    "no " + name + " under PITH_CDYLIB_DIR=" + directory.toAbsolutePath()
                            + " (or relative to any search root)");
        }
        // An unsupported platform just means nothing is bundled for it; keep the
        // checkout lookup below working and name the platform in the final error.
        String platformNote = "";
        try {
            String bundled = extractBundled(
                    platformId(System.getProperty("os.name", ""), System.getProperty("os.arch", "")), name);
            if (bundled != null) {
                return bundled;
            }
        } catch (PithLibraryNotFoundException e) {
            platformNote = "; " + e.getMessage();
        }
        for (Path base : searchRoots()) {
            Path candidate = base.resolve("target").resolve("release").resolve(name);
            if (Files.isRegularFile(candidate)) {
                return candidate.toAbsolutePath().toString();
            }
        }
        throw new PithLibraryNotFoundException(
                "no " + name + " found: set PITH_CDYLIB or PITH_CDYLIB_DIR, "
                        + "or run `cargo build --release` in the repository" + platformNote);
    }

    /** The nearest ancestor directory (or the working directory) holding {@code reference.json}. */
    static Path repoRoot() {
        for (Path base : searchRoots()) {
            if (Files.isRegularFile(base.resolve("reference.json"))) {
                return base;
            }
        }
        throw new PithLibraryNotFoundException(
                "no reference.json above " + Paths.get("").toAbsolutePath());
    }

    private static List<Path> searchRoots() {
        List<Path> roots = new ArrayList<>();
        Path current = Paths.get("").toAbsolutePath();
        for (int depth = 0; depth < 4 && current != null; depth++) {
            roots.add(current);
            current = current.getParent();
        }
        return roots;
    }

    private static String cdylibName(String stem) {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        if (os.contains("win")) {
            return stem + ".dll";
        }
        if (os.contains("mac") || os.contains("darwin")) {
            return "lib" + stem + ".dylib";
        }
        return "lib" + stem + ".so";
    }
}
