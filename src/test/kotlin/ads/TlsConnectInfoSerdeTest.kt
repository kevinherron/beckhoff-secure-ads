package ads

import ads.TlsConnectInfo.*
import io.netty.buffer.Unpooled
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class TlsConnectInfoSerdeTest {

  @Test
  fun `roundtrip without credentials`() {
    val original =
        TlsConnectInfo(
            length = Serde.BASE_SIZE.toUShort(),
            flags = setOf(Flag.AMS_ALLOWED, Flag.SELF_SIGNED),
            version = 1u,
            error = TlsError.NO_ERROR,
            amsNetId = AmsNetId("10.20.30.40.1.1"),
            reserved = ByteArray(18),
            hostName = "MY-HOST",
            credentials = null,
        )

    val decoded = encodeAndDecode(original)

    assertEquals(original, decoded)
  }

  @Test
  fun `roundtrip with credentials`() {
    val user = "admin"
    val password = "secret123"
    val length = Serde.BASE_SIZE + user.length + password.length

    val original =
        TlsConnectInfo(
            length = length.toUShort(),
            flags = setOf(Flag.ADD_REMOTE),
            version = 1u,
            error = TlsError.NO_ERROR,
            amsNetId = AmsNetId("192.168.1.100.1.1"),
            reserved = ByteArray(18),
            hostName = "WORKSTATION",
            credentials = Pair(user, password),
        )

    val decoded = encodeAndDecode(original)

    assertEquals(original, decoded)
  }

  @Test
  fun `roundtrip with all flags`() {
    val original =
        TlsConnectInfo(
            length = Serde.BASE_SIZE.toUShort(),
            flags = Flag.entries.toSet(),
            version = 1u,
            error = TlsError.NO_ERROR,
            amsNetId = AmsNetId("1.2.3.4.5.6"),
            reserved = ByteArray(18),
            hostName = "ALL-FLAGS",
            credentials = null,
        )

    val decoded = encodeAndDecode(original)

    assertEquals(original, decoded)
  }

  @Test
  fun `roundtrip with error code`() {
    val original =
        TlsConnectInfo(
            length = Serde.BASE_SIZE.toUShort(),
            flags = setOf(Flag.RESPONSE),
            version = 1u,
            error = TlsError.CN_MISMATCH,
            amsNetId = AmsNetId("10.0.0.1.1.1"),
            reserved = ByteArray(18),
            hostName = "SERVER",
            credentials = null,
        )

    val decoded = encodeAndDecode(original)

    assertEquals(original, decoded)
  }

  @Test
  fun `roundtrip with max-length hostname`() {
    val maxHostName = "A".repeat(32)

    val original =
        TlsConnectInfo(
            length = Serde.BASE_SIZE.toUShort(),
            flags = setOf(),
            version = 1u,
            error = TlsError.NO_ERROR,
            amsNetId = AmsNetId("0.0.0.0.0.0"),
            reserved = ByteArray(18),
            hostName = maxHostName,
            credentials = null,
        )

    val decoded = encodeAndDecode(original)

    assertEquals(original, decoded)
  }

  @Test
  fun `decode advances reader index`() {
    val info =
        TlsConnectInfo(
            length = Serde.BASE_SIZE.toUShort(),
            flags = setOf(),
            version = 1u,
            error = TlsError.NO_ERROR,
            amsNetId = AmsNetId("1.2.3.4.5.6"),
            reserved = ByteArray(18),
            hostName = "HOST",
            credentials = null,
        )

    val buffer = Unpooled.buffer()
    Serde.encode(info, buffer)
    // append trailing byte to verify decode consumes exactly `length` bytes
    buffer.writeByte(0xFF)

    Serde.decode(buffer)

    assertEquals(1, buffer.readableBytes())
  }

  @Test
  fun `decode advances reader index with credentials`() {
    val user = "user"
    val password = "pass"
    val length = Serde.BASE_SIZE + user.length + password.length

    val info =
        TlsConnectInfo(
            length = length.toUShort(),
            flags = setOf(),
            version = 1u,
            error = TlsError.NO_ERROR,
            amsNetId = AmsNetId("1.2.3.4.5.6"),
            reserved = ByteArray(18),
            hostName = "HOST",
            credentials = Pair(user, password),
        )

    val buffer = Unpooled.buffer()
    Serde.encode(info, buffer)
    buffer.writeByte(0xFF)

    Serde.decode(buffer)

    assertEquals(1, buffer.readableBytes())
  }

  @Test
  fun `decode fails with insufficient bytes`() {
    val buffer = Unpooled.buffer()
    buffer.writeBytes(ByteArray(10))

    assertFailsWith<IllegalArgumentException> { Serde.decode(buffer) }
  }

  @Test
  fun `decode fails with length out of range`() {
    val buffer = Unpooled.buffer()
    // write a length smaller than BASE_SIZE
    buffer.writeShortLE(2)
    buffer.writeBytes(ByteArray(62))

    assertFailsWith<IllegalArgumentException> { Serde.decode(buffer) }
  }

  private fun encodeAndDecode(info: TlsConnectInfo): TlsConnectInfo {
    val buffer = Unpooled.buffer()
    Serde.encode(info, buffer)
    return Serde.decode(buffer)
  }
}
