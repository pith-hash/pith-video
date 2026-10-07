package hash.pith;

/** No suite cdylib could be located for {@link System#load}.
 *
 * <p>Thrown by the discovery chain ({@code PITH_CDYLIB} →
 * {@code PITH_CDYLIB_DIR} → {@code target/release} of the working
 * directory or an ancestor) when none of its stops holds the platform
 * cdylib. Building the repository with {@code cargo build --release}
 * fixes the common case.
 */
public class PithLibraryNotFoundException extends IllegalStateException {
    private static final long serialVersionUID = 1L;

    /** @param message what was searched and where */
    public PithLibraryNotFoundException(String message) {
        super(message);
    }
}
