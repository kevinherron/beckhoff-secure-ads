package ads

import io.netty.buffer.ByteBuf
import java.nio.charset.Charset

/**
 * Models the TlsConnectInfo request/response exchanged after the TLS handshake on Secure ADS port
 * 8016. This is the first application-layer message in both directions.
 *
 * @property length total message length (uint16 LE).
 * @property flags connection flags.
 * @property version protocol version.
 * @property error error code (meaningful in responses).
 * @property amsNetId 6-byte AMS Net ID.
 * @property reserved 18 reserved bytes.
 * @property hostName null-padded hostname (32 bytes on wire).
 * @property credentials optional user/password pair (windows-1252). Either both are present or
 *   neither.
 */
data class TlsConnectInfo(
    val length: UShort,
    val flags: Set<Flag>,
    val version: UByte,
    val error: TlsError,
    val amsNetId: AmsNetId,
    val reserved: ByteArray,
    val hostName: String,
    val credentials: Pair<String, String>?,
) {

  companion object {
    /** The wire charset used by the TLS Connect Info protocol for all string fields. */
    val CHARSET: Charset = Charset.forName("windows-1252")
  }

  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (other !is TlsConnectInfo) return false

    if (length != other.length) return false
    if (flags != other.flags) return false
    if (version != other.version) return false
    if (error != other.error) return false
    if (!amsNetId.netId.contentEquals(other.amsNetId.netId)) return false
    if (!reserved.contentEquals(other.reserved)) return false
    if (hostName != other.hostName) return false
    if (credentials != other.credentials) return false

    return true
  }

  override fun hashCode(): Int {
    var result = length.hashCode()
    result = 31 * result + flags.hashCode()
    result = 31 * result + version.hashCode()
    result = 31 * result + error.hashCode()
    result = 31 * result + amsNetId.netId.contentHashCode()
    result = 31 * result + reserved.contentHashCode()
    result = 31 * result + hostName.hashCode()
    result = 31 * result + (credentials?.hashCode() ?: 0)
    return result
  }

  override fun toString(): String {
    return buildString {
      append("TlsConnectInfo[")
      append("length=").append(length)
      append(", flags=").append(flags)
      append(", version=").append(version)
      append(", error=").append(error)
      append(", amsNetId=").append(amsNetId)
      append(", hostName=").append(hostName)
      if (credentials != null) {
        append(", user=").append(credentials.first)
        append(", password=***")
      }
      append("]")
    }
  }

  enum class Flag(val bit: Int) {
    RESPONSE(0x01),
    AMS_ALLOWED(0x02),
    SERVER_INFO(0x04),
    OWN_FILE(0x08),
    SELF_SIGNED(0x10),
    IP_ADDR(0x20),
    IGNORE_CN(0x40),
    ADD_REMOTE(0x80);

    companion object {
      fun fromUint16(value: Int): Set<Flag> {
        return entries.filterTo(mutableSetOf()) { value and it.bit != 0 }
      }

      fun toUint16(flags: Set<Flag>): Int {
        return flags.fold(0) { acc, flag -> acc or flag.bit }
      }
    }
  }

  enum class TlsError(val code: Int) {
    NO_ERROR(0),
    VERSION(1),
    CN_MISMATCH(2),
    UNKNOWN_CERT(3),
    UNKNOWN_USER(4),
    UNKNOWN(-1);

    companion object {
      fun fromByte(value: Int): TlsError {
        return entries.firstOrNull { it.code == value } ?: UNKNOWN
      }
    }
  }

  object Serde {

    /** Minimum (and base) size of a TlsConnectInfo message on the wire. */
    const val BASE_SIZE: Int = 64

    private const val MAX_SIZE: Int = 512
    private const val HOSTNAME_LENGTH: Int = 32

    /** Encode [info] into the provided [buffer]. */
    fun encode(info: TlsConnectInfo, buffer: ByteBuf) {
      val userBytes = info.credentials?.first?.toByteArray(CHARSET)
      val passwordBytes = info.credentials?.second?.toByteArray(CHARSET)
      val userLen = userBytes?.size ?: 0
      val passwordLen = passwordBytes?.size ?: 0

      require(userLen in 0..255) {
        "username too long for 1-byte length field: $userLen bytes (max 255)"
      }
      require(passwordLen in 0..255) {
        "password too long for 1-byte length field: $passwordLen bytes (max 255)"
      }

      val expectedLength = BASE_SIZE + userLen + passwordLen
      require(info.length.toInt() == expectedLength) {
        "length field ${info.length} does not match encoded size $expectedLength"
      }
      require(expectedLength <= MAX_SIZE) {
        "encoded size $expectedLength exceeds maximum $MAX_SIZE"
      }

      buffer.writeShortLE(info.length.toInt())
      buffer.writeShortLE(Flag.toUint16(info.flags))
      buffer.writeByte(info.version.toInt())
      buffer.writeByte(info.error.code)
      buffer.writeBytes(info.amsNetId.netId)

      buffer.writeByte(userLen)
      buffer.writeByte(passwordLen)
      buffer.writeBytes(info.reserved)

      // HostName: 32-byte null-padded field
      val hostNameBytes = info.hostName.toByteArray(CHARSET)
      val copyLength = minOf(hostNameBytes.size, HOSTNAME_LENGTH)
      buffer.writeBytes(hostNameBytes, 0, copyLength)
      buffer.writeZero(HOSTNAME_LENGTH - copyLength)

      // Variable-length credential fields
      if (userBytes != null) {
        buffer.writeBytes(userBytes)
      }
      if (passwordBytes != null) {
        buffer.writeBytes(passwordBytes)
      }
    }

    /**
     * Decode a [TlsConnectInfo] from the provided [buffer].
     *
     * Advances the buffer's reader index by [length] bytes.
     *
     * @throws IllegalArgumentException if there are insufficient bytes or the length field is out
     *   of range.
     */
    fun decode(buffer: ByteBuf): TlsConnectInfo {
      val readable = buffer.readableBytes()

      require(readable >= BASE_SIZE) { "not enough readable bytes: $readable < $BASE_SIZE" }

      val length = buffer.readUnsignedShortLE()
      require(length in BASE_SIZE..MAX_SIZE) {
        "length out of range: $length (expected $BASE_SIZE..$MAX_SIZE)"
      }
      require(readable >= length) {
        "not enough readable bytes for declared length: $readable < $length"
      }
      val flags = Flag.fromUint16(buffer.readUnsignedShortLE())
      val version = buffer.readUnsignedByte().toUByte()
      val error = TlsError.fromByte(buffer.readUnsignedByte().toInt())

      val amsNetId = AmsNetId(ByteArray(AmsNetId.NET_ID_LENGTH).apply { buffer.readBytes(this) })
      val userLength = buffer.readUnsignedByte().toInt()
      val passwordLength = buffer.readUnsignedByte().toInt()
      val reserved = ByteArray(18).apply { buffer.readBytes(this) }

      val hostNameBytes = ByteArray(HOSTNAME_LENGTH).apply { buffer.readBytes(this) }
      val hostName = String(hostNameBytes, CHARSET).trimEnd('\u0000')

      // Variable-length credential fields (all-or-nothing)
      require((userLength > 0) == (passwordLength > 0)) {
        "credentials must come as a pair: userLength=$userLength, passwordLength=$passwordLength"
      }

      val credentials =
          if (userLength > 0) {
            val userBytes = ByteArray(userLength).apply { buffer.readBytes(this) }
            val passwordBytes = ByteArray(passwordLength).apply { buffer.readBytes(this) }
            Pair(String(userBytes, CHARSET), String(passwordBytes, CHARSET))
          } else {
            null
          }

      return TlsConnectInfo(
          length = length.toUShort(),
          flags = flags,
          version = version,
          error = error,
          amsNetId = amsNetId,
          reserved = reserved,
          hostName = hostName,
          credentials = credentials,
      )
    }
  }
}
