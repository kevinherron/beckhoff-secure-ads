package ads.client

import ads.*
import ads.commands.AdsReadDeviceInfoResponse
import ads.commands.AdsReadStateResponse
import ads.netty.AmsFrameCodec
import ads.netty.TlsConnectInfoHandler
import io.netty.bootstrap.Bootstrap
import io.netty.buffer.ByteBuf
import io.netty.buffer.Unpooled
import io.netty.channel.*
import io.netty.channel.socket.SocketChannel
import io.netty.channel.socket.nio.NioSocketChannel
import io.netty.handler.ssl.SslHandler
import io.netty.util.Timeout
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.withTimeout
import org.slf4j.LoggerFactory

class AdsClient(val config: AdsClientConfig) {

  companion object {
    private val logger = LoggerFactory.getLogger(AdsClient::class.java)
  }

  private val invokeIds = AtomicLong(0)

  private val pendingRequests = ConcurrentHashMap<UInt, PendingRequest>()

  @Volatile private var channel: Channel? = null
  @Volatile private var disconnecting: Boolean = false

  /**
   * Establishes a connection to the ADS device specified in the [config].
   *
   * This method initiates a TCP connection to the target ADS device using the hostname and port
   * configured in [AdsClientConfig]. When [AdsClientConfig.secureAdsConfig] is provided, the
   * connection is secured with TLS.
   *
   * @return A [Result] that is successful if the connection was established, or contains an
   *   exception if the connection failed.
   */
  suspend fun connect(): Result<Unit> = runCatching {
    disconnecting = false

    val secureAdsConfig = config.secureAdsConfig

    val (channelInitializer, tlsConnectInfoDeferred) =
        if (secureAdsConfig != null) {
          val sslContext = buildSslContext(secureAdsConfig)
          val deferred = CompletableDeferred<TlsConnectInfo>()
          val tlsConnectInfoHandler =
              TlsConnectInfoHandler(
                  buildTlsConnectInfoRequest(secureAdsConfig, config.sourceNetId),
                  deferred,
              )

          val initializer =
              object : ChannelInitializer<SocketChannel>() {
                override fun initChannel(ch: SocketChannel) {
                  val sslEngine =
                      sslContext.newEngine(ch.alloc(), config.hostname, config.port.toInt())
                  sslEngine.enabledProtocols = PROTOCOLS
                  ch.pipeline().addLast("ssl", SslHandler(sslEngine))
                  ch.pipeline().addLast("tls-connect-info", tlsConnectInfoHandler)
                  ch.pipeline().addLast("ams-frame-codec", AmsFrameCodec(includeTcpHeader = false))
                  ch.pipeline().addLast("inbound-frame-handler", InboundFrameHandler())
                }
              }

          Pair(initializer, deferred)
        } else {
          val initializer =
              object : ChannelInitializer<SocketChannel>() {
                override fun initChannel(ch: SocketChannel) {
                  ch.pipeline().addLast("ams-frame-codec", AmsFrameCodec(includeTcpHeader = true))
                  ch.pipeline().addLast("inbound-frame-handler", InboundFrameHandler())
                }
              }

          Pair(initializer, null)
        }

    val channelDeferred = CompletableDeferred<Channel>()

    Bootstrap()
        .group(Shared.sharedEventLoopGroup())
        .channel(NioSocketChannel::class.java)
        .option(
            ChannelOption.CONNECT_TIMEOUT_MILLIS,
            config.connectTimeout.inWholeMilliseconds.toInt(),
        )
        .handler(channelInitializer)
        .connect(config.hostname, config.port.toInt())
        .addListener(
            ChannelFutureListener { cf ->
              if (cf.isSuccess) {
                channelDeferred.complete(cf.channel())
              } else {
                channelDeferred.completeExceptionally(cf.cause())
              }
            },
        )

    channel = channelDeferred.await()

    if (tlsConnectInfoDeferred != null) {
      try {
        withTimeout(config.connectTimeout) { tlsConnectInfoDeferred.await() }
      } catch (e: Exception) {
        channel?.close()
        channel = null
        throw e
      }
    }
  }

  /**
   * Closes the connection to the ADS device.
   *
   * This method gracefully disconnects from the ADS device by closing the underlying TCP channel.
   * After disconnection, no further ADS commands can be sent until [connect] is called again.
   *
   * @return A [Result] that is successful if the disconnection completed, or contains an exception
   *   if an error occurred during disconnection.
   */
  suspend fun disconnect(): Result<Unit> = runCatching {
    disconnecting = true
    channel?.close()?.await()
    channel = null
    failAllPendingRequests(Exception("client disconnected"))
  }

  suspend fun readState(): Result<AdsReadStateResponse> = runCatching {
    val frame: AmsFrame = send(AdsCommand.ADS_READ_STATE, Unpooled.EMPTY_BUFFER).getOrThrow()

    try {
      frame.header.checkReturnCode()

      AdsReadStateResponse.Serde.decode(frame.data)
    } finally {
      frame.data.release()
    }
  }

  suspend fun readDeviceInfo(): Result<AdsReadDeviceInfoResponse> = runCatching {
    val frame: AmsFrame = send(AdsCommand.ADS_READ_DEVICE_INFO, Unpooled.EMPTY_BUFFER).getOrThrow()

    try {
      frame.header.checkReturnCode()

      AdsReadDeviceInfoResponse.Serde.decode(frame.data)
    } finally {
      frame.data.release()
    }
  }

  private suspend fun send(command: AdsCommand, data: ByteBuf): Result<AmsFrame> = runCatching {
    val ch: Channel = channel ?: throw IllegalStateException("not connected; call connect() first")

    val invokeId: UInt = invokeIds.incrementAndGet().toUInt()

    val header =
        AmsHeader(
            config.targetNetId,
            config.targetPort,
            config.sourceNetId,
            config.sourcePort,
            command,
            flags = AmsHeaderFlags.Companion.ADS_COMMAND_REQUEST,
            length = data.readableBytes().toUInt(),
            errorCode = 0u,
            invokeId,
        )

    logger.debug(
        "Sending request: command={}, invokeId={}, target={}:{}, source={}:{}, dataSize={}",
        command,
        invokeId,
        config.targetNetId,
        config.targetPort.port,
        config.sourceNetId,
        config.sourcePort.port,
        data.readableBytes(),
    )

    val deferred = CompletableDeferred<AmsFrame>()

    val timeout: Timeout =
        Shared.sharedWheelTimer()
            .newTimeout(
                {
                  val pending = pendingRequests.remove(invokeId)
                  if (pending != null) {
                    logger.warn(
                        "Request timeout: command={}, invokeId={}, pendingCount={}",
                        command,
                        invokeId,
                        pendingRequests.size,
                    )
                    pending.deferred.completeExceptionally(
                        TimeoutException("Request timeout for invokeId=$invokeId")
                    )
                  }
                },
                config.requestTimeout.inWholeMilliseconds,
                TimeUnit.MILLISECONDS,
            )

    pendingRequests[invokeId] = PendingRequest(deferred, timeout)

    ch.writeAndFlush(AmsFrame(header, data)).addListener {
      if (!it.isSuccess) {
        logger.error("Write failed: command={}, invokeId={}", command, invokeId, it.cause())
        pendingRequests.remove(invokeId)?.let { pending ->
          pending.timeout.cancel()
          pending.deferred.completeExceptionally(it.cause())
        }
      }
    }

    runCatching { deferred.await() }
        .onFailure { pendingRequests.remove(invokeId)?.timeout?.cancel() }
        .getOrThrow()
  }

  private fun handleDeviceNotificationFrame(frame: AmsFrame) {
    logger.warn("received device notification frame (not yet implemented), releasing")
    frame.data.release()
  }

  private fun failAllPendingRequests(cause: Exception) {
    val iterator = pendingRequests.entries.iterator()
    while (iterator.hasNext()) {
      val entry = iterator.next()
      iterator.remove()
      entry.value.timeout.cancel()
      entry.value.deferred.completeExceptionally(cause)
    }
  }

  /**
   * Checks that the return code in [this] [AmsHeader] is 0 (indicating success) and throws
   * [AdsException] if it is not.
   */
  private fun AmsHeader.checkReturnCode() {
    if (errorCode != 0u) {
      val adsErrorCode: AdsErrorCode = AdsErrorCode.Companion.from(errorCode)
      throw AdsException(adsErrorCode, "command [$command] failed: $adsErrorCode")
    }
  }

  private data class PendingRequest(
      val deferred: CompletableDeferred<AmsFrame>,
      val timeout: Timeout,
  )

  inner class InboundFrameHandler : SimpleChannelInboundHandler<AmsFrame>() {

    override fun channelRead0(ctx: ChannelHandlerContext, frame: AmsFrame) {
      val header = frame.header
      logger.debug(
          "Received frame: command={}, invokeId={}, flags={}, errorCode={}, dataSize={}",
          header.command,
          header.invokeId,
          header.flags,
          header.errorCode,
          header.length,
      )

      if (header.command == AdsCommand.ADS_DEVICE_NOTIFICATION) {
        handleDeviceNotificationFrame(frame)
      } else {
        val invokeId: UInt = header.invokeId
        val pending = pendingRequests.remove(invokeId)

        if (pending != null) {
          pending.timeout.cancel()
          pending.deferred.complete(frame)
        } else {
          logger.warn(
              "Received response for unknown invokeId={}, command={}, releasing",
              invokeId,
              header.command,
          )
          frame.data.release()
        }
      }
    }

    override fun channelInactive(ctx: ChannelHandlerContext) {
      if (disconnecting) {
        logger.debug("channel inactive (disconnect), pendingRequests={}", pendingRequests.size)
      } else {
        logger.warn("channel inactive, pendingRequests={}", pendingRequests.size)
      }
      channel = null
      failAllPendingRequests(Exception("channel inactive"))
      ctx.fireChannelInactive()
    }

    override fun exceptionCaught(ctx: ChannelHandlerContext, cause: Throwable) {
      logger.error("Exception in pipeline", cause)
      ctx.close()
    }
  }
}
