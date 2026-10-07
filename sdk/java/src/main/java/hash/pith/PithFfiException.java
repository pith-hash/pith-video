package hash.pith;

/** A suite cdylib operation refused with a flat status code.
 *
 * <p>Mirrors the Python/Node/Go {@code FfiError}: {@code 0} is success
 * and never thrown; {@code -1} marks an invalid caller argument and
 * {@code -2} a core refusal (malformed container, unsupported codec,
 * a limit exceeded). The Rust side never unwinds into the JVM — it
 * throws this exception and returns a null the wrapper never sees.
 */
public class PithFfiException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    private final String op;
    private final int status;

    /** @param op the refusing operation (its C symbol name)
     *  @param status the flat status code ({@code -1} invalid, {@code -2} rejected) */
    public PithFfiException(String op, int status) {
        super(op + " failed with status " + status);
        this.op = op;
        this.status = status;
    }

    /** The refusing operation (its C symbol name). */
    public String getOp() {
        return op;
    }

    /** The flat status code: {@code -1} invalid argument, {@code -2} core refusal. */
    public int getStatus() {
        return status;
    }
}
