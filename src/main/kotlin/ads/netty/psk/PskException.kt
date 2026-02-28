package ads.netty.psk

/**
 * Exception type for PSK TLS errors, providing structured error classification.
 *
 * Each exception carries an [ErrorType] that categorizes the failure for programmatic handling,
 * plus a user-friendly message. The underlying TLS alert or transport exception is preserved as the
 * [cause] for debugging.
 *
 * Security note: messages never include PSK key material, identities, or raw TLS record bytes.
 *
 * @property errorType the classified error category
 */
class PskException(
    val errorType: ErrorType,
    message: String,
    cause: Throwable? = null,
) : Exception(message, cause) {

  /** Categorized PSK error types for structured error handling. */
  enum class ErrorType {
    /** TLS handshake failed due to cipher suite mismatch or invalid PSK. */
    NO_COMPATIBLE_SUITE,

    /** PSK identity or key was rejected by the remote peer. */
    AUTHENTICATION_FAILED,

    /** TLS protocol error (version mismatch, illegal parameter, unexpected message). */
    PROTOCOL_ERROR,

    /** Internal error reported by the remote TLS peer. */
    INTERNAL_ERROR,

    /** Connection closed by remote peer (close_notify). */
    CONNECTION_CLOSED,

    /** Underlying transport (I/O) error. */
    TRANSPORT_ERROR,

    /** Handshake did not complete within the configured timeout. */
    HANDSHAKE_TIMEOUT,

    /** Unrecognized TLS alert or error. */
    UNKNOWN,
  }

  override fun toString(): String {
    return "PskException[$errorType]: $message"
  }
}
