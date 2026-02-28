package ads.netty.psk

/**
 * Handshake completion event fired by [BouncyCastlePskHandler] when a PSK handshake completes.
 *
 * This allows [ads.netty.TlsConnectInfoHandler] to react to PSK handshake completion in the same
 * way it reacts to [io.netty.handler.ssl.SslHandshakeCompletionEvent] for TLS certificate-based
 * connections.
 *
 * @property isSuccess `true` if the handshake completed successfully.
 * @property cause the Exception that caused the handshake to fail or `null` if successful.
 */
class PskHandshakeCompletionEvent
private constructor(
    val isSuccess: Boolean,
    val cause: Throwable?,
) {
  companion object {
    /** A singleton success event. */
    val SUCCESS = PskHandshakeCompletionEvent(isSuccess = true, cause = null)

    /** Creates a failure event with the given [cause]. */
    fun failure(cause: Throwable) = PskHandshakeCompletionEvent(isSuccess = false, cause = cause)
  }

  override fun toString(): String {
    return if (isSuccess) {
      "PskHandshakeCompletionEvent(SUCCESS)"
    } else {
      "PskHandshakeCompletionEvent(FAILURE, cause=${cause?.message})"
    }
  }
}
