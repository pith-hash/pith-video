package hash.pith;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
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
 *   <li>the {@code target/release} directory of the working directory
 *       or one of its ancestors (a plain repository checkout).</li>
 * </ol>
 */
final class PithNative {
    private PithNative() {
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
        for (Path base : searchRoots()) {
            Path candidate = base.resolve("target").resolve("release").resolve(name);
            if (Files.isRegularFile(candidate)) {
                return candidate.toAbsolutePath().toString();
            }
        }
        throw new PithLibraryNotFoundException(
                "no " + name + " found: set PITH_CDYLIB or PITH_CDYLIB_DIR, "
                        + "or run `cargo build --release` in the repository");
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
