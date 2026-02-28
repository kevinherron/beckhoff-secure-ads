import ads.TlsConnectInfo
import io.netty.bootstrap.Bootstrap
import io.netty.buffer.ByteBuf
import io.netty.channel.ChannelHandlerContext
import io.netty.channel.ChannelInitializer
import io.netty.channel.ChannelOption
import io.netty.channel.MultiThreadIoEventLoopGroup
import io.netty.channel.nio.NioIoHandler
import io.netty.channel.socket.SocketChannel
import io.netty.channel.socket.nio.NioSocketChannel
import io.netty.handler.codec.ByteToMessageDecoder
import io.netty.handler.ssl.SslContext
import io.netty.handler.ssl.SslHandler
import io.netty.handler.ssl.SslHandshakeCompletionEvent
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

val TLS_CIPHER_SUITES =
    listOf(
        "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
        "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
        "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    )

val TLS_PROTOCOLS = arrayOf("TLSv1.2")

fun connectAndAddRoute(
    sslContext: SslContext,
    request: TlsConnectInfo,
) {
  val group = MultiThreadIoEventLoopGroup(1, NioIoHandler.newFactory())
  val latch = CountDownLatch(1)

  try {
    val bootstrap =
        Bootstrap()
            .group(group)
            .channel(NioSocketChannel::class.java)
            .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, 5000)
            .handler(
                object : ChannelInitializer<SocketChannel>() {
                  override fun initChannel(ch: SocketChannel) {
                    val sslEngine =
                        sslContext.newEngine(
                            ch.alloc(),
                            Config.TARGET_HOST,
                            Config.TARGET_PORT.toInt(),
                        )
                    sslEngine.enabledProtocols = TLS_PROTOCOLS
                    ch.pipeline().addLast("ssl", SslHandler(sslEngine))
                    ch.pipeline().addLast("add-route", AddRouteHandler(request, latch))
                  }
                },
            )

    println("Connecting to ${Config.TARGET_HOST}:${Config.TARGET_PORT}...")
    val cf = bootstrap.connect(Config.TARGET_HOST, Config.TARGET_PORT.toInt()).sync()

    if (!cf.isSuccess) {
      System.err.println("Connect failed: ${cf.cause()}")
      return
    }

    println("Connected, waiting for route registration...")
    if (!latch.await(15, TimeUnit.SECONDS)) {
      System.err.println("Timed out waiting for route registration response")
      cf.channel().close().syncUninterruptibly()
    }
  } catch (e: Exception) {
    System.err.println("Error: ${e.message}")
    e.printStackTrace()
  } finally {
    group.shutdownGracefully().sync()
  }
}

private class AddRouteHandler(
    private val request: TlsConnectInfo,
    private val latch: CountDownLatch,
) : ByteToMessageDecoder() {
  override fun userEventTriggered(
      ctx: ChannelHandlerContext,
      evt: Any,
  ) {
    if (evt is SslHandshakeCompletionEvent) {
      if (evt.isSuccess) {
        val sslHandler = ctx.pipeline().get(SslHandler::class.java)
        val peerCerts = sslHandler.engine().session.peerCertificates
        println("TLS handshake complete")
        println(
            "  Peer certificate: ${(peerCerts[0] as java.security.cert.X509Certificate).subjectX500Principal}",
        )
        println("  Sending AddRoute request: $request")

        val buffer = ctx.alloc().buffer(request.length.toInt())
        TlsConnectInfo.Serde.encode(request, buffer)
        ctx.writeAndFlush(buffer)
      } else {
        System.err.println("TLS handshake failed: ${evt.cause()}")
        evt.cause().printStackTrace()
        latch.countDown()
      }
    }
    ctx.fireUserEventTriggered(evt)
  }

  override fun decode(
      ctx: ChannelHandlerContext,
      buffer: ByteBuf,
      out: MutableList<Any>,
  ) {
    if (buffer.readableBytes() < 2) return

    val length = buffer.getUnsignedShortLE(buffer.readerIndex())
    if (buffer.readableBytes() < length) return

    val response = TlsConnectInfo.Serde.decode(buffer)

    println("Received TlsConnectInfo response: $response")

    if (response.error != TlsConnectInfo.TlsError.NO_ERROR) {
      System.err.println("AddRoute failed: ${response.error}")
    } else {
      println("Route added successfully!")
    }

    ctx.close()
    latch.countDown()
  }

  override fun exceptionCaught(
      ctx: ChannelHandlerContext,
      cause: Throwable,
  ) {
    System.err.println("Exception: ${cause.message}")
    cause.printStackTrace()
    ctx.close()
    latch.countDown()
  }

  override fun channelInactive(ctx: ChannelHandlerContext) {
    latch.countDown()
    ctx.fireChannelInactive()
  }
}
