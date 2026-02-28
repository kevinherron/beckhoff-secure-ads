package ads.netty.psk

import io.netty.buffer.ByteBuf
import io.netty.buffer.Unpooled
import io.netty.channel.ChannelDuplexHandler
import io.netty.channel.ChannelHandlerContext
import io.netty.channel.ChannelPromise
import java.io.IOException
import java.util.*
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import org.bouncycastle.tls.*
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto
import org.slf4j.LoggerFactory

/**
 * Netty channel handler that performs TLS-PSK using Bouncy Castle's non-blocking TLS API.
 *
 * This handler sits at the front of the pipeline and:
 * - Encrypts outbound plaintext into TLS records before writing to the socket.
 * - Decrypts inbound TLS records into plaintext before passing upstream.
 * - Fires [PskHandshakeCompletionEvent] when the handshake completes or fails.
 *
 * Design notes:
 * - Uses [TlsClientProtocol] in non-blocking mode (no streams passed to constructor).
 * - All operations run on the Netty event loop thread — no blocking.
 * - Critical: [TwinCatPskTlsClient.getClientExtensions] returns `null` because TwinCAT rejects
 *   ClientHellos containing extensions like `extended_master_secret` and `encrypt_then_mac`.
 *
 * @param identity the PSK identity bytes
 * @param psk the pre-shared key bytes (32 bytes for SHA-256 derived keys)
 * @param offeredCipherSuites the TLS cipher suites to offer (defaults to 4 AES-CBC suites)
 * @param handshakeTimeoutMillis maximum time allowed for the TLS handshake to complete (0 = no
 *   timeout)
 */
class BouncyCastlePskHandler(
    private val identity: ByteArray,
    private val psk: ByteArray,
    private val offeredCipherSuites: IntArray = DEFAULT_CIPHER_SUITES,
    private val handshakeTimeoutMillis: Long = DEFAULT_HANDSHAKE_TIMEOUT_MILLIS,
) : ChannelDuplexHandler() {

  companion object {
    private val logger = LoggerFactory.getLogger(BouncyCastlePskHandler::class.java)

    /** Maximum buffered plaintext bytes before handshake completes. */
    private const val MAX_PENDING_PLAINTEXT = 256 * 1024

    /** Buffer size for reading from BC protocol. */
    private const val READ_BUFFER_SIZE = 16 * 1024

    /** Default handshake timeout in milliseconds. */
    const val DEFAULT_HANDSHAKE_TIMEOUT_MILLIS = 5000L

    /** Default cipher suites ordered by preference (the strongest MAC first). */
    val DEFAULT_CIPHER_SUITES =
        intArrayOf(
            CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA384,
            CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256,
            CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA,
            CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA,
        )
  }

  private lateinit var protocol: TlsClientProtocol
  private lateinit var tlsClient: TwinCatPskTlsClient

  @Volatile private var handshakeComplete = false
  private var handshakeFailed = false

  /** Scheduled future for handshake timeout; canceled on completion or failure. */
  private var handshakeTimeoutFuture: ScheduledFuture<*>? = null

  /**
   * Plaintext writes that arrived before the handshake completed. Drained once the handshake
   * succeeds.
   */
  private val pendingWrites = LinkedList<PendingWrite>()
  private var pendingWriteBytes = 0

  override fun channelActive(ctx: ChannelHandlerContext) {
    logger.debug("Channel active, initiating PSK TLS handshake")

    protocol = TlsClientProtocol()
    tlsClient =
        TwinCatPskTlsClient(
            identity = identity,
            psk = psk,
            offeredCipherSuites = offeredCipherSuites,
        )

    // Schedule handshake timeout
    if (handshakeTimeoutMillis > 0) {
      handshakeTimeoutFuture =
          ctx.executor()
              .schedule(
                  {
                    if (!handshakeComplete && !handshakeFailed) {
                      val cause =
                          PskException(
                              PskException.ErrorType.HANDSHAKE_TIMEOUT,
                              "PSK TLS handshake timed out after ${handshakeTimeoutMillis}ms",
                          )
                      logger.warn("PSK TLS handshake timeout after {}ms", handshakeTimeoutMillis)
                      failHandshake(ctx, cause)
                    }
                  },
                  handshakeTimeoutMillis,
                  TimeUnit.MILLISECONDS,
              )
    }

    try {
      // Initiate the handshake — this generates the ClientHello
      protocol.connect(tlsClient)

      // Drain the ClientHello output and send it
      drainOutputToChannel(ctx)
    } catch (e: Exception) {
      logger.error("Failed to initiate PSK TLS handshake", e)
      failHandshake(ctx, e)
      return
    }

    // channelActive is safe to propagate — TlsConnectInfoHandler
    // triggers on PskHandshakeCompletionEvent, not channelActive.
    ctx.fireChannelActive()
  }

  override fun channelRead(ctx: ChannelHandlerContext, msg: Any) {
    if (msg !is ByteBuf) {
      ctx.fireChannelRead(msg)
      return
    }

    try {
      // Feed ciphertext into BC protocol
      val bytes = ByteArray(msg.readableBytes())
      msg.readBytes(bytes)

      protocol.offerInput(bytes)

      if (!handshakeComplete) {
        // Check if handshake just completed
        if (protocol.isConnected) {
          handshakeComplete = true
          cancelHandshakeTimeout()

          val version = tlsClient.negotiatedVersion
          val suite = tlsClient.negotiatedCipherSuite
          logger.info(
              "PSK TLS handshake complete: version={}, cipher={}",
              version,
              suite?.let { cipherSuiteName(it) } ?: "unknown",
          )

          // Drain any handshake output
          drainOutputToChannel(ctx)

          // Fire success event
          ctx.fireUserEventTriggered(PskHandshakeCompletionEvent.SUCCESS)

          // Drain pending writes
          drainPendingWrites(ctx)
        } else {
          // Still handshaking — drain outbound handshake records
          drainOutputToChannel(ctx)
        }
      }

      // Read any available plaintext
      drainPlaintextUpstream(ctx)

      // Drain any protocol output generated during reads
      drainOutputToChannel(ctx)
    } catch (e: Exception) {
      if (!handshakeComplete) {
        failHandshake(ctx, mapException(e))
      } else {
        logger.error("Error processing inbound TLS data", e)
        ctx.fireExceptionCaught(mapException(e))
      }
    } finally {
      msg.release()
    }
  }

  override fun write(ctx: ChannelHandlerContext, msg: Any, promise: ChannelPromise) {
    if (msg !is ByteBuf) {
      ctx.write(msg, promise)
      return
    }

    if (handshakeFailed) {
      msg.release()
      promise.setFailure(IllegalStateException("PSK TLS handshake has failed"))
      return
    }

    if (!handshakeComplete) {
      // Buffer writes until handshake completes
      val bytes = ByteArray(msg.readableBytes())
      msg.readBytes(bytes)
      msg.release()

      pendingWriteBytes += bytes.size
      if (pendingWriteBytes > MAX_PENDING_PLAINTEXT) {
        promise.setFailure(
            IllegalStateException(
                "Pending plaintext exceeds $MAX_PENDING_PLAINTEXT bytes during handshake"
            )
        )
        return
      }

      pendingWrites.add(PendingWrite(bytes, promise))
      return
    }

    try {
      val bytes = ByteArray(msg.readableBytes())
      msg.readBytes(bytes)
      msg.release()

      protocol.writeApplicationData(bytes, 0, bytes.size)
      drainOutputToChannel(ctx, promise)
    } catch (e: Exception) {
      promise.setFailure(mapException(e))
    }
  }

  override fun channelInactive(ctx: ChannelHandlerContext) {
    if (!handshakeComplete && !handshakeFailed) {
      failHandshake(ctx, Exception("Channel closed during PSK TLS handshake"))
    }

    failPendingWrites(Exception("Channel closed"))

    try {
      protocol.close()
    } catch (_: Exception) {
      // ignore close errors
    }

    ctx.fireChannelInactive()
  }

  override fun exceptionCaught(ctx: ChannelHandlerContext, cause: Throwable) {
    if (!handshakeComplete && !handshakeFailed) {
      failHandshake(ctx, cause)
    } else {
      ctx.fireExceptionCaught(cause)
    }
  }

  /** Drains decrypted plaintext from the BC protocol and fires it upstream as [ByteBuf]s. */
  private fun drainPlaintextUpstream(ctx: ChannelHandlerContext) {
    val buf = ByteArray(READ_BUFFER_SIZE)
    while (true) {
      val available = protocol.getAvailableInputBytes()
      if (available <= 0) break

      val read = protocol.readInput(buf, 0, buf.size)
      if (read <= 0) break

      ctx.fireChannelRead(Unpooled.copiedBuffer(buf, 0, read))
    }
  }

  /** Drains TLS output records from the BC protocol and writes them to the channel. */
  private fun drainOutputToChannel(ctx: ChannelHandlerContext, promise: ChannelPromise? = null) {
    val available = protocol.getAvailableOutputBytes()
    if (available <= 0) {
      promise?.setSuccess()
      return
    }

    val output = ByteArray(available)
    val read = protocol.readOutput(output, 0, available)
    if (read > 0) {
      val buf = Unpooled.wrappedBuffer(output, 0, read)
      if (promise != null) {
        ctx.writeAndFlush(buf, promise)
      } else {
        ctx.writeAndFlush(buf)
      }
    } else {
      promise?.setSuccess()
    }
  }

  /** Drains pending writes that were buffered during the handshake. */
  private fun drainPendingWrites(ctx: ChannelHandlerContext) {
    while (pendingWrites.isNotEmpty()) {
      val pending = pendingWrites.poll() ?: break
      try {
        protocol.writeApplicationData(pending.data, 0, pending.data.size)
        drainOutputToChannel(ctx, pending.promise)
      } catch (e: Exception) {
        pending.promise.setFailure(mapException(e))
      }
    }
    pendingWriteBytes = 0
  }

  private fun failPendingWrites(cause: Exception) {
    while (pendingWrites.isNotEmpty()) {
      val pending = pendingWrites.poll() ?: break
      pending.promise.setFailure(cause)
    }
    pendingWriteBytes = 0
  }

  private fun cancelHandshakeTimeout() {
    handshakeTimeoutFuture?.cancel(false)
    handshakeTimeoutFuture = null
  }

  private fun failHandshake(ctx: ChannelHandlerContext, cause: Throwable) {
    if (handshakeFailed) return
    handshakeFailed = true
    cancelHandshakeTimeout()

    logger.error("PSK TLS handshake failed: {}", cause.message)

    failPendingWrites(Exception("PSK TLS handshake failed", cause))

    ctx.fireUserEventTriggered(PskHandshakeCompletionEvent.failure(cause))
    ctx.close()
  }

  /**
   * Maps low-level BC exceptions to more user-friendly [PskException] errors.
   *
   * Raw TLS alert details are kept at debug level via BC's
   * `notifyAlertReceived`/`notifyAlertRaised` callbacks. The mapped exceptions provide actionable
   * messages without leaking internal TLS state.
   */
  private fun mapException(e: Throwable): Throwable {
    if (e is TlsFatalAlert) {
      val desc = e.alertDescription
      return when (desc) {
        AlertDescription.handshake_failure ->
            PskException(
                PskException.ErrorType.NO_COMPATIBLE_SUITE,
                "PSK TLS handshake failed — no compatible cipher suite or invalid PSK identity/key",
                e,
            )
        AlertDescription.internal_error ->
            PskException(
                PskException.ErrorType.INTERNAL_ERROR,
                "PSK TLS internal error on remote peer",
                e,
            )
        AlertDescription.decrypt_error ->
            PskException(
                PskException.ErrorType.AUTHENTICATION_FAILED,
                "PSK authentication failed — invalid identity or key",
                e,
            )
        AlertDescription.illegal_parameter ->
            PskException(
                PskException.ErrorType.PROTOCOL_ERROR,
                "PSK TLS illegal parameter — protocol version or extension mismatch",
                e,
            )
        AlertDescription.protocol_version ->
            PskException(
                PskException.ErrorType.PROTOCOL_ERROR,
                "PSK TLS protocol version not supported by remote peer",
                e,
            )
        AlertDescription.unexpected_message ->
            PskException(
                PskException.ErrorType.PROTOCOL_ERROR,
                "PSK TLS unexpected message received",
                e,
            )
        AlertDescription.close_notify ->
            PskException(
                PskException.ErrorType.CONNECTION_CLOSED,
                "PSK TLS connection closed by remote peer",
                e,
            )
        else ->
            PskException(
                PskException.ErrorType.UNKNOWN,
                "PSK TLS alert: ${AlertDescription.getText(desc)}",
                e,
            )
      }
    }
    if (e is IOException) {
      return PskException(
          PskException.ErrorType.TRANSPORT_ERROR,
          "PSK TLS transport error: ${e.message}",
          e,
      )
    }
    return e
  }

  private data class PendingWrite(
      val data: ByteArray,
      val promise: ChannelPromise,
  ) {

    override fun equals(other: Any?): Boolean {
      if (this === other) return true
      if (javaClass != other?.javaClass) return false

      other as PendingWrite

      if (!data.contentEquals(other.data)) return false
      if (promise != other.promise) return false

      return true
    }

    override fun hashCode(): Int {
      var result = data.contentHashCode()
      result = 31 * result + promise.hashCode()
      return result
    }
  }

  /**
   * BC TLS client configured for TwinCAT PSK compatibility.
   *
   * Key constraints:
   * - TLS 1.2 only
   * - Pure PSK cipher suites only (no DHE_PSK, no ECDHE_PSK)
   * - No ClientHello extensions (TwinCAT rejects them)
   */
  private class TwinCatPskTlsClient(
      identity: ByteArray,
      psk: ByteArray,
      private val offeredCipherSuites: IntArray,
  ) : PSKTlsClient(BcTlsCrypto(), BasicTlsPSKIdentity(identity, psk)) {

    var negotiatedVersion: ProtocolVersion? = null
      private set

    var negotiatedCipherSuite: Int? = null
      private set

    override fun getSupportedVersions(): Array<ProtocolVersion> = ProtocolVersion.TLSv12.only()

    override fun getSupportedCipherSuites(): IntArray =
        TlsUtils.getSupportedCipherSuites(crypto, offeredCipherSuites)

    /**
     * Returns `null` to strip all ClientHello extensions. TwinCAT's embedded TLS rejects
     * ClientHellos containing extensions it doesn't recognize (extended_master_secret,
     * encrypt_then_mac, etc. that BC adds by default).
     */
    override fun getClientExtensions(): Hashtable<*, *>? = null

    override fun notifyServerVersion(serverVersion: ProtocolVersion) {
      super.notifyServerVersion(serverVersion)
      negotiatedVersion = serverVersion
    }

    override fun notifySelectedCipherSuite(selectedCipherSuite: Int) {
      super.notifySelectedCipherSuite(selectedCipherSuite)
      negotiatedCipherSuite = selectedCipherSuite
    }

    override fun notifyAlertRaised(
        alertLevel: Short,
        alertDescription: Short,
        message: String?,
        cause: Throwable?,
    ) {
      logger.debug(
          "TLS alert raised: {}/{}{}",
          AlertLevel.getText(alertLevel),
          AlertDescription.getText(alertDescription),
          if (message != null) " ($message)" else "",
      )
      super.notifyAlertRaised(alertLevel, alertDescription, message, cause)
    }

    override fun notifyAlertReceived(alertLevel: Short, alertDescription: Short) {
      logger.debug(
          "TLS alert received: {}/{}",
          AlertLevel.getText(alertLevel),
          AlertDescription.getText(alertDescription),
      )
      super.notifyAlertReceived(alertLevel, alertDescription)
    }
  }
}

private fun cipherSuiteName(suite: Int): String {
  return when (suite) {
    CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA384 -> "TLS_PSK_WITH_AES_256_CBC_SHA384"
    CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256 -> "TLS_PSK_WITH_AES_128_CBC_SHA256"
    CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA -> "TLS_PSK_WITH_AES_256_CBC_SHA"
    CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA -> "TLS_PSK_WITH_AES_128_CBC_SHA"
    else -> "0x${suite.toString(16).uppercase().padStart(4, '0')}"
  }
}
