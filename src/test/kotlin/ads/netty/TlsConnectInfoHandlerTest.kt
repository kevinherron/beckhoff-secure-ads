package ads.netty

import ads.AmsNetId
import ads.TlsConnectInfo
import ads.netty.psk.PskHandshakeCompletionEvent
import io.netty.buffer.Unpooled
import io.netty.channel.embedded.EmbeddedChannel
import io.netty.handler.ssl.SslHandshakeCompletionEvent
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout

class TlsConnectInfoHandlerTest {

  private val sourceNetId = AmsNetId("10.20.30.40.1.1")
  private val serverNetId = AmsNetId("192.168.1.100.1.1")

  private fun makeRequest(): TlsConnectInfo {
    return TlsConnectInfo(
        length = TlsConnectInfo.Serde.BASE_SIZE.toUShort(),
        flags = emptySet(),
        version = 1u,
        error = TlsConnectInfo.TlsError.NO_ERROR,
        amsNetId = sourceNetId,
        reserved = ByteArray(18),
        hostName = "TEST-HOST",
        credentials = null,
    )
  }

  private fun makeResponse(
      error: TlsConnectInfo.TlsError = TlsConnectInfo.TlsError.NO_ERROR,
  ): TlsConnectInfo {
    return TlsConnectInfo(
        length = TlsConnectInfo.Serde.BASE_SIZE.toUShort(),
        flags = setOf(TlsConnectInfo.Flag.RESPONSE, TlsConnectInfo.Flag.AMS_ALLOWED),
        version = 1u,
        error = error,
        amsNetId = serverNetId,
        reserved = ByteArray(18),
        hostName = "PLC-HOST",
        credentials = null,
    )
  }

  @Test
  fun `handler reacts to PskHandshakeCompletionEvent`() = runBlocking {
    val deferred = CompletableDeferred<TlsConnectInfo>()
    val handler = TlsConnectInfoHandler(makeRequest(), deferred)
    val channel = EmbeddedChannel(handler)

    // Fire PSK handshake success event
    channel.pipeline().fireUserEventTriggered(PskHandshakeCompletionEvent.SUCCESS)

    // Handler should have written the request
    val outbound = channel.readOutbound<io.netty.buffer.ByteBuf>()
    assertNotNull(outbound, "Expected TlsConnectInfo request to be written")
    assertTrue(outbound.readableBytes() >= TlsConnectInfo.Serde.BASE_SIZE)
    outbound.release()

    // Feed a successful response
    val responseBuf = Unpooled.buffer()
    TlsConnectInfo.Serde.encode(makeResponse(), responseBuf)
    channel.writeInbound(responseBuf)

    // Verify the deferred completes successfully
    val result = withTimeout(1000) { deferred.await() }
    assertEquals(TlsConnectInfo.TlsError.NO_ERROR, result.error)

    channel.close()
  }

  @Test
  fun `handler reacts to SslHandshakeCompletionEvent`() = runBlocking {
    val deferred = CompletableDeferred<TlsConnectInfo>()
    val handler = TlsConnectInfoHandler(makeRequest(), deferred)
    val channel = EmbeddedChannel(handler)

    // Fire SSL handshake success event
    channel.pipeline().fireUserEventTriggered(SslHandshakeCompletionEvent.SUCCESS)

    // Handler should have written the request
    val outbound = channel.readOutbound<io.netty.buffer.ByteBuf>()
    assertNotNull(outbound, "Expected TlsConnectInfo request to be written")
    outbound.release()

    // Feed a successful response
    val responseBuf = Unpooled.buffer()
    TlsConnectInfo.Serde.encode(makeResponse(), responseBuf)
    channel.writeInbound(responseBuf)

    val result = withTimeout(1000) { deferred.await() }
    assertEquals(TlsConnectInfo.TlsError.NO_ERROR, result.error)

    channel.close()
  }

  @Test
  fun `handler completes exceptionally on PskHandshakeCompletionEvent failure`() = runBlocking {
    val deferred = CompletableDeferred<TlsConnectInfo>()
    val handler = TlsConnectInfoHandler(makeRequest(), deferred)
    val channel = EmbeddedChannel(handler)

    val cause = RuntimeException("handshake failed")
    channel.pipeline().fireUserEventTriggered(PskHandshakeCompletionEvent.failure(cause))

    assertTrue(deferred.isCompleted)
    val exception = runCatching { deferred.await() }.exceptionOrNull()
    assertNotNull(exception)
    assertEquals("handshake failed", exception.message)

    channel.close()
  }

  @Test
  fun `handler completes exceptionally on SslHandshakeCompletionEvent failure`() = runBlocking {
    val deferred = CompletableDeferred<TlsConnectInfo>()
    val handler = TlsConnectInfoHandler(makeRequest(), deferred)
    val channel = EmbeddedChannel(handler)

    val cause = RuntimeException("ssl failed")
    channel.pipeline().fireUserEventTriggered(SslHandshakeCompletionEvent(cause))

    assertTrue(deferred.isCompleted)
    val exception = runCatching { deferred.await() }.exceptionOrNull()
    assertNotNull(exception)
    assertEquals("ssl failed", exception.message)

    channel.close()
  }

  @Test
  fun `handler completes exceptionally on error response`() = runBlocking {
    val deferred = CompletableDeferred<TlsConnectInfo>()
    val handler = TlsConnectInfoHandler(makeRequest(), deferred)
    val channel = EmbeddedChannel(handler)

    channel.pipeline().fireUserEventTriggered(PskHandshakeCompletionEvent.SUCCESS)
    drainOutbound(channel)

    // Feed an error response
    val responseBuf = Unpooled.buffer()
    TlsConnectInfo.Serde.encode(
        makeResponse(error = TlsConnectInfo.TlsError.UNKNOWN_USER),
        responseBuf,
    )
    channel.writeInbound(responseBuf)

    assertTrue(deferred.isCompleted)
    val exception = runCatching { deferred.await() }.exceptionOrNull()
    assertNotNull(exception)
    assertTrue(exception.message?.contains("UNKNOWN_USER") == true)

    // Channel should be closed on error
    channel.close()
  }

  @Test
  fun `handler completes exceptionally on channel inactive`() = runBlocking {
    val deferred = CompletableDeferred<TlsConnectInfo>()
    val handler = TlsConnectInfoHandler(makeRequest(), deferred)
    val channel = EmbeddedChannel(handler)

    // Close channel without completing the exchange
    channel.close()

    assertTrue(deferred.isCompleted)
    val exception = runCatching { deferred.await() }.exceptionOrNull()
    assertNotNull(exception)
    assertTrue(exception.message?.contains("Channel closed") == true)
  }

  @Test
  fun `handler removes itself from pipeline after success`() = runBlocking {
    val deferred = CompletableDeferred<TlsConnectInfo>()
    val handler = TlsConnectInfoHandler(makeRequest(), deferred)
    val channel = EmbeddedChannel(handler)

    channel.pipeline().fireUserEventTriggered(PskHandshakeCompletionEvent.SUCCESS)
    drainOutbound(channel)

    val responseBuf = Unpooled.buffer()
    TlsConnectInfo.Serde.encode(makeResponse(), responseBuf)
    channel.writeInbound(responseBuf)

    withTimeout(1000) { deferred.await() }

    // Handler should have removed itself
    val handlerInPipeline = channel.pipeline().get(TlsConnectInfoHandler::class.java)
    assertEquals(null, handlerInPipeline, "Handler should remove itself after success")

    channel.close()
  }

  @Test
  fun `handler waits for complete response before decoding`() = runBlocking {
    val deferred = CompletableDeferred<TlsConnectInfo>()
    val handler = TlsConnectInfoHandler(makeRequest(), deferred)
    val channel = EmbeddedChannel(handler)

    channel.pipeline().fireUserEventTriggered(PskHandshakeCompletionEvent.SUCCESS)
    drainOutbound(channel)

    // Feed response in two parts
    val responseBuf = Unpooled.buffer()
    TlsConnectInfo.Serde.encode(makeResponse(), responseBuf)

    val part1 = responseBuf.readBytes(10)
    val part2 = responseBuf.readBytes(responseBuf.readableBytes())

    channel.writeInbound(part1)
    // Should not be complete yet
    assertTrue(!deferred.isCompleted, "Should not decode from partial data")

    channel.writeInbound(part2)
    // Now should be complete
    val result = withTimeout(1000) { deferred.await() }
    assertEquals(TlsConnectInfo.TlsError.NO_ERROR, result.error)

    responseBuf.release()
    channel.close()
  }

  private fun drainOutbound(channel: EmbeddedChannel) {
    while (true) {
      val buf = channel.readOutbound<io.netty.buffer.ByteBuf>() ?: break
      buf.release()
    }
  }
}
