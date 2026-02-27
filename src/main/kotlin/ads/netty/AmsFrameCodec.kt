package ads.netty

import ads.AmsFrame
import ads.AmsHeader
import io.netty.buffer.ByteBuf
import io.netty.channel.ChannelHandlerContext
import io.netty.handler.codec.ByteToMessageCodec
import io.netty.handler.codec.TooLongFrameException
import org.slf4j.LoggerFactory

/**
 * Codec for encoding/decoding [AmsFrame] instances.
 *
 * @param includeTcpHeader when `true`, the 6-byte AMS/TCP header (2 reserved bytes + 4-byte length)
 *   is written on encode and expected on decode. Set to `false` for Secure ADS connections where
 *   TLS provides the transport framing.
 */
class AmsFrameCodec(private val includeTcpHeader: Boolean = true) : ByteToMessageCodec<AmsFrame>() {

  companion object {
    private val logger = LoggerFactory.getLogger(AmsFrameCodec::class.java)

    /** Fixed size of the AMS header fields, in bytes. */
    private const val AMS_HEADER_SIZE = 32

    /** Size of the AMS/TCP header (2 reserved + 4 length). */
    private const val TCP_HEADER_SIZE = 6

    /**
     * Maximum allowed frame length (AMS header and data payload). Frames exceeding this limit are
     * rejected to prevent unbounded buffer growth from malformed or malicious length fields. 4 MB
     * is well above any legitimate ADS payload.
     */
    private const val MAX_FRAME_LENGTH = 4 * 1024 * 1024
  }

  override fun encode(ctx: ChannelHandlerContext, frame: AmsFrame, out: ByteBuf) {
    val header = frame.header

    if (includeTcpHeader) {
      out.writeByte(0)
      out.writeByte(0)
      out.writeIntLE(AMS_HEADER_SIZE + frame.data.readableBytes())
    }

    AmsHeader.Serde.encode(header, out)
    out.writeBytes(frame.data)

    frame.data.release()
  }

  override fun decode(ctx: ChannelHandlerContext, buffer: ByteBuf, out: MutableList<Any>) {
    if (includeTcpHeader) {
      decodeTcp(buffer, out)
    } else {
      decodeRaw(buffer, out)
    }
  }

  private fun decodeTcp(buffer: ByteBuf, out: MutableList<Any>) {
    if (buffer.readableBytes() >= TCP_HEADER_SIZE) {
      // The first 2 bytes are reserved, should be zeros.
      // The next 4 bytes are the overall length of the AmsHeader and data.
      val lengthUnsigned = buffer.getUnsignedIntLE(buffer.readerIndex() + 2)

      if (lengthUnsigned !in AMS_HEADER_SIZE..MAX_FRAME_LENGTH) {
        buffer.skipBytes(buffer.readableBytes())
        throw TooLongFrameException(
            "TCP frame length out of range: $lengthUnsigned" +
                " (expected $AMS_HEADER_SIZE..$MAX_FRAME_LENGTH)"
        )
      }

      val length = lengthUnsigned.toInt()

      if (buffer.readableBytes() >= length + TCP_HEADER_SIZE) {
        buffer.skipBytes(TCP_HEADER_SIZE)

        decodeFrame(buffer, out)
      } else {
        logger.trace(
            "Incomplete frame: need {} bytes, have {} readable",
            length + TCP_HEADER_SIZE,
            buffer.readableBytes(),
        )
      }
    }
  }

  private fun decodeRaw(buffer: ByteBuf, out: MutableList<Any>) {
    if (buffer.readableBytes() >= AMS_HEADER_SIZE) {
      buffer.markReaderIndex()

      // Peek at the data length field (offset 24 in AMS header, 4 bytes LE)
      val dataLengthUnsigned = buffer.getUnsignedIntLE(buffer.readerIndex() + 24)
      val frameLength = AMS_HEADER_SIZE.toLong() + dataLengthUnsigned

      if (frameLength > MAX_FRAME_LENGTH) {
        buffer.skipBytes(buffer.readableBytes())
        throw TooLongFrameException(
            "raw frame length out of range: $frameLength" + " (max $MAX_FRAME_LENGTH)"
        )
      }

      val dataLength = dataLengthUnsigned.toInt()

      if (buffer.readableBytes() >= AMS_HEADER_SIZE + dataLength) {
        decodeFrame(buffer, out)
      } else {
        buffer.resetReaderIndex()
        logger.trace(
            "Incomplete frame: need {} bytes, have {} readable",
            AMS_HEADER_SIZE + dataLength,
            buffer.readableBytes(),
        )
      }
    }
  }

  private fun decodeFrame(buffer: ByteBuf, out: MutableList<Any>) {
    val header: AmsHeader = AmsHeader.Serde.decode(buffer)
    val data: ByteBuf = buffer.readRetainedSlice(header.length.toInt())

    out += AmsFrame(header, data)
  }
}
