package ads.netty.psk

import io.netty.buffer.ByteBuf
import io.netty.buffer.Unpooled
import io.netty.channel.ChannelHandlerContext
import io.netty.channel.ChannelInboundHandlerAdapter
import io.netty.channel.embedded.EmbeddedChannel
import kotlin.test.*

class BouncyCastlePskHandlerTest {

  private val validIdentity = "test-identity".toByteArray(Charsets.UTF_8)
  private val validPsk = ByteArray(32) { it.toByte() } // dummy 32-byte PSK

  @Test
  fun `handler generates ClientHello on channel active`() {
    val handler =
        BouncyCastlePskHandler(
            identity = validIdentity,
            psk = validPsk,
            handshakeTimeoutMillis = 0, // disable timeout for unit test
        )
    val channel = EmbeddedChannel(handler)

    // The handler should have written the ClientHello to the outbound
    val outbound = channel.readOutbound<ByteBuf>()
    assertNotNull(outbound, "Expected ClientHello output")
    assertTrue(outbound.readableBytes() > 0, "ClientHello should be non-empty")
    outbound.release()

    channel.close()
  }

  @Test
  fun `write before handshake completes is buffered`() {
    val handler =
        BouncyCastlePskHandler(
            identity = validIdentity,
            psk = validPsk,
            handshakeTimeoutMillis = 0,
        )
    val channel = EmbeddedChannel(handler)

    // Drain ClientHello
    drainOutbound(channel)

    // Write plaintext before handshake completes — should be buffered
    val data = Unpooled.wrappedBuffer("hello".toByteArray())
    channel.writeOutbound(data)

    // No additional outbound data should appear (it's buffered, not sent as plaintext)
    val outbound = channel.readOutbound<ByteBuf>()
    assertNull(outbound, "Write should be buffered during handshake, not sent")

    channel.close()
  }

  @Test
  fun `garbage input during handshake closes channel`() {
    val handler =
        BouncyCastlePskHandler(
            identity = validIdentity,
            psk = validPsk,
            handshakeTimeoutMillis = 0,
        )
    val channel = EmbeddedChannel(handler)
    drainOutbound(channel)

    // Feed garbage to trigger handshake failure
    try {
      channel.writeInbound(Unpooled.wrappedBuffer(ByteArray(64) { 0xFF.toByte() }))
    } catch (_: Exception) {
      // Expected — handler closes channel
    }

    // Channel should be closed after handshake failure
    assertFalse(channel.isOpen, "Channel should be closed after handshake failure")
  }

  @Test
  fun `write after handshake failed returns failure`() {
    val handler =
        BouncyCastlePskHandler(
            identity = validIdentity,
            psk = validPsk,
            handshakeTimeoutMillis = 0,
        )
    val channel = EmbeddedChannel(handler)
    drainOutbound(channel)

    // Feed garbage to trigger handshake failure
    try {
      channel.writeInbound(Unpooled.wrappedBuffer(ByteArray(64) { 0xFF.toByte() }))
    } catch (_: Exception) {
      // Expected
    }

    // Now attempt a write after the handshake has failed
    val data = Unpooled.wrappedBuffer("hello".toByteArray())
    var writeFailed = false
    try {
      channel.writeOutbound(data)
    } catch (_: Exception) {
      writeFailed = true
    }

    assertTrue(writeFailed, "Write after handshake failure should fail")
  }

  @Test
  fun `invalid ciphertext triggers handshake failure event`() {
    var failureEvent: PskHandshakeCompletionEvent? = null

    val handler =
        BouncyCastlePskHandler(
            identity = validIdentity,
            psk = validPsk,
            handshakeTimeoutMillis = 0,
        )

    val eventCapture =
        object : ChannelInboundHandlerAdapter() {
          override fun userEventTriggered(ctx: ChannelHandlerContext, evt: Any) {
            if (evt is PskHandshakeCompletionEvent && !evt.isSuccess) {
              failureEvent = evt
            }
            ctx.fireUserEventTriggered(evt)
          }
        }

    val channel = EmbeddedChannel(handler, eventCapture)
    drainOutbound(channel)

    // Feed garbage ciphertext
    try {
      channel.writeInbound(Unpooled.wrappedBuffer(ByteArray(100) { 0xAB.toByte() }))
    } catch (_: Exception) {
      // Expected — handler closes channel
    }

    val event = failureEvent
    assertNotNull(event, "Expected PskHandshakeCompletionEvent(failure)")
    assertFalse(event.isSuccess)
    assertNotNull(event.cause)
  }

  @Test
  fun `channelInactive during handshake fires failure event`() {
    var failureEvent: PskHandshakeCompletionEvent? = null

    val handler =
        BouncyCastlePskHandler(
            identity = validIdentity,
            psk = validPsk,
            handshakeTimeoutMillis = 0,
        )

    val eventCapture =
        object : ChannelInboundHandlerAdapter() {
          override fun userEventTriggered(ctx: ChannelHandlerContext, evt: Any) {
            if (evt is PskHandshakeCompletionEvent && !evt.isSuccess) {
              failureEvent = evt
            }
            ctx.fireUserEventTriggered(evt)
          }
        }

    val channel = EmbeddedChannel(handler, eventCapture)
    drainOutbound(channel)

    // Close channel during handshake
    channel.close()

    val event2 = failureEvent
    assertNotNull(event2, "Expected failure event on channel close during handshake")
    assertFalse(event2.isSuccess)
  }

  @Test
  fun `pending writes exceeded limit fails promise`() {
    val handler =
        BouncyCastlePskHandler(
            identity = validIdentity,
            psk = validPsk,
            handshakeTimeoutMillis = 0,
        )
    val channel = EmbeddedChannel(handler)
    drainOutbound(channel)

    // Write more than MAX_PENDING_PLAINTEXT (256KB)
    val largeData = Unpooled.wrappedBuffer(ByteArray(257 * 1024))
    var writeFailed = false
    try {
      channel.writeOutbound(largeData)
    } catch (_: Exception) {
      writeFailed = true
    }

    // The first large write might succeed (buffered), but subsequent should fail
    // or the single large one should fail
    // Since MAX_PENDING_PLAINTEXT is 256*1024, writing 257*1024 should fail
    assertTrue(writeFailed, "Expected write to fail when exceeding pending plaintext limit")

    channel.close()
  }

  private fun drainOutbound(channel: EmbeddedChannel) {
    while (true) {
      val buf = channel.readOutbound<ByteBuf>() ?: break
      buf.release()
    }
  }
}
