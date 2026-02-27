package ads.netty

import ads.TlsConnectInfo
import io.netty.buffer.ByteBuf
import io.netty.channel.ChannelHandlerContext
import io.netty.handler.codec.ByteToMessageDecoder
import io.netty.handler.ssl.SslHandshakeCompletionEvent
import kotlinx.coroutines.CompletableDeferred
import org.slf4j.LoggerFactory

/**
 * Handles the TlsConnectInfo request/response exchange that occurs immediately after the TLS
 * handshake on Secure ADS connections.
 *
 * This handler sits between [io.netty.handler.ssl.SslHandler] and [AmsFrameCodec] in the pipeline.
 * Once the exchange completes successfully, it removes itself from the pipeline.
 *
 * @param request the [TlsConnectInfo] request to send after the TLS handshake completes.
 * @param result a [CompletableDeferred] that will be completed with the server's response, or
 *   completed exceptionally if an error occurs.
 */
class TlsConnectInfoHandler(
    private val request: TlsConnectInfo,
    private val result: CompletableDeferred<TlsConnectInfo>,
) : ByteToMessageDecoder() {

  companion object {
    private val logger = LoggerFactory.getLogger(TlsConnectInfoHandler::class.java)
  }

  override fun userEventTriggered(ctx: ChannelHandlerContext, evt: Any) {
    if (evt is SslHandshakeCompletionEvent) {
      if (evt.isSuccess) {
        logger.info("tx -> $request")

        val buffer = ctx.alloc().buffer(request.length.toInt())
        TlsConnectInfo.Serde.encode(request, buffer)
        ctx.writeAndFlush(buffer)
      } else {
        logger.error("TLS handshake failed", evt.cause())
        result.completeExceptionally(evt.cause())
      }
    }

    ctx.fireUserEventTriggered(evt)
  }

  override fun decode(ctx: ChannelHandlerContext, buffer: ByteBuf, out: MutableList<Any>) {
    if (buffer.readableBytes() < 2) return

    val length = buffer.getUnsignedShortLE(buffer.readerIndex())
    if (buffer.readableBytes() < length) return

    val response = TlsConnectInfo.Serde.decode(buffer)
    buffer.skipBytes(length)

    logger.info("rx <- $response")

    if (response.error != TlsConnectInfo.TlsError.NO_ERROR) {
      val ex = Exception("TlsConnectInfo exchange failed: ${response.error}")
      result.completeExceptionally(ex)
      ctx.close()
      return
    }

    result.complete(response)
    ctx.pipeline().remove(this)
  }

  override fun channelInactive(ctx: ChannelHandlerContext) {
    result.completeExceptionally(Exception("Channel closed during TlsConnectInfo exchange"))
    ctx.fireChannelInactive()
  }

  override fun exceptionCaught(ctx: ChannelHandlerContext, cause: Throwable) {
    result.completeExceptionally(cause)
    ctx.close()
  }
}
