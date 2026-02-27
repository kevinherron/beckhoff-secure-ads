package ads

import io.netty.buffer.ByteBuf

/**
 * Represents an AMS Header structure used in the Beckhoff ADS protocol.
 *
 * @property target the target AMS net ID (network address).
 * @property targetPort the target AMS port number.
 * @property source the source AMS net ID.
 * @property sourcePort the source AMS port number.
 * @property command the ADS command to be executed.
 * @property flags the AMS header flags indicating request/response status.
 * @property length the length of the data following this header.
 * @property errorCode the error code (0 if no error).
 * @property invokeId the ID used to match requests with responses.
 */
data class AmsHeader(
    val target: AmsNetId,
    val targetPort: AmsPort,
    val source: AmsNetId,
    val sourcePort: AmsPort,
    val command: AdsCommand,
    val flags: AmsHeaderFlags,
    val length: UInt,
    val errorCode: UInt,
    val invokeId: UInt,
) {

  override fun hashCode(): Int {
    var result = target.netId.contentHashCode()
    result = 31 * result + targetPort.hashCode()
    result = 31 * result + source.netId.contentHashCode()
    result = 31 * result + sourcePort.hashCode()
    result = 31 * result + command.hashCode()
    result = 31 * result + flags.hashCode()
    result = 31 * result + length.hashCode()
    result = 31 * result + errorCode.hashCode()
    result = 31 * result + invokeId.hashCode()
    return result
  }

  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (other !is AmsHeader) return false

    if (!target.netId.contentEquals(other.target.netId)) return false
    if (targetPort != other.targetPort) return false
    if (!source.netId.contentEquals(other.source.netId)) return false
    if (sourcePort != other.sourcePort) return false
    if (command != other.command) return false
    if (flags != other.flags) return false
    if (length != other.length) return false
    if (errorCode != other.errorCode) return false
    if (invokeId != other.invokeId) return false

    return true
  }

  object Serde {

    /** Encode [header] into the provided [buffer]. */
    fun encode(header: AmsHeader, buffer: ByteBuf) {
      buffer.writeBytes(header.target.netId)
      buffer.writeShortLE(header.targetPort.port.toInt())
      buffer.writeBytes(header.source.netId)
      buffer.writeShortLE(header.sourcePort.port.toInt())
      buffer.writeShortLE(header.command.id.toInt())
      buffer.writeShortLE(header.flags.flags.toInt())
      buffer.writeIntLE(header.length.toInt())
      buffer.writeIntLE(header.errorCode.toInt())
      buffer.writeIntLE(header.invokeId.toInt())
    }

    /** Decode an [AmsHeader] from the provided [buffer]. */
    fun decode(buffer: ByteBuf): AmsHeader {
      val target = ByteArray(AmsNetId.NET_ID_LENGTH).apply { buffer.readBytes(this) }
      val targetPort: UShort = buffer.readUnsignedShortLE().toUShort()
      val source = ByteArray(AmsNetId.NET_ID_LENGTH).apply { buffer.readBytes(this) }
      val sourcePort: UShort = buffer.readUnsignedShortLE().toUShort()
      val command: AdsCommand =
          AdsCommand.fromId(buffer.readUnsignedShortLE())
              ?: throw IllegalArgumentException("unknown command id")
      val flags: UInt = buffer.readUnsignedShortLE().toUInt()
      val length: UInt = buffer.readUnsignedIntLE().toUInt()
      val errorCode: UInt = buffer.readUnsignedIntLE().toUInt()
      val invokeId: UInt = buffer.readUnsignedIntLE().toUInt()

      return AmsHeader(
          target = AmsNetId(target),
          targetPort = AmsPort(targetPort),
          source = AmsNetId(source),
          sourcePort = AmsPort(sourcePort),
          command = command,
          flags = AmsHeaderFlags(flags),
          length = length,
          errorCode = errorCode,
          invokeId = invokeId,
      )
    }
  }
}

@JvmInline
value class AmsHeaderFlags(val flags: UInt) {

  companion object {
    /** Flags indicating this is an ADS command request. */
    val ADS_COMMAND_REQUEST = AmsHeaderFlags(0x04u)

    /** Flags indicating this is an ADS command response. */
    val ADS_COMMAND_RESPONSE = AmsHeaderFlags(0x04u or 0x01u)
  }

  /** Flags indicate this is a request. */
  val request: Boolean
    get() = !response

  /** Flags indicate this is a response. */
  val response: Boolean
    get() = flags and 0x01u == 0x01u

  /** Flags indicate this is an ADS command. */
  val adsCommand: Boolean
    get() = flags and 0x04u == 0x04u

  override fun toString(): String {
    val parts = mutableListOf<String>()
    if (response) parts += "RESPONSE" else parts += "REQUEST"
    if (adsCommand) parts += "ADS_COMMAND"
    return "AmsHeaderFlags(0x${flags.toString(16).padStart(4, '0')}, ${parts.joinToString("|")})"
  }
}
