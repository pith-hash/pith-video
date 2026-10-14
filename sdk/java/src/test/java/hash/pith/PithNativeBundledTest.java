package hash.pith;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermissions;
import org.junit.jupiter.api.Test;

class PithNativeBundledTest {
    @Test
    void platformIdMapsOsAndArch() {
        assertEquals("linux-x64", PithNative.platformId("Linux", "amd64"));
        assertEquals("linux-arm64", PithNative.platformId("Linux", "aarch64"));
        assertEquals("darwin-arm64", PithNative.platformId("Mac OS X", "aarch64"));
        assertEquals("darwin-x64", PithNative.platformId("Mac OS X", "x86_64"));
        assertEquals("win32-x64", PithNative.platformId("Windows 11", "amd64"));
    }

    @Test
    void unsupportedPlatformIsNamedInTheError() {
        PithLibraryNotFoundException e = assertThrows(
                PithLibraryNotFoundException.class, () -> PithNative.platformId("FreeBSD", "sparc"));
        assertTrue(e.getMessage().contains("freebsd-sparc"), e.getMessage());
    }

    @Test
    void extractsBundledResourceToAFreshPrivateDirectory() throws Exception {
        String first = PithNative.extractBundled("test-platform", "fake.bin");
        String second = PithNative.extractBundled("test-platform", "fake.bin");
        assertEquals("fake-native", Files.readString(Paths.get(first)).trim());
        assertNotEquals(first, second, "each call must use its own directory");
        Path dir = Paths.get(first).getParent();
        if (Files.getFileStore(dir).supportsFileAttributeView("posix")) {
            assertEquals("rwx------", PosixFilePermissions.toString(Files.getPosixFilePermissions(dir)));
        }
    }

    @Test
    void missingResourceReturnsNull() {
        assertNull(PithNative.extractBundled("test-platform", "absent.bin"));
    }
}
