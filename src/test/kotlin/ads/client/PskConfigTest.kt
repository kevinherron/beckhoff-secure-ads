package ads.client

import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotSame
import kotlin.test.assertTrue

class PskConfigTest {

  // --- fromPassword ---

  @Test
  fun `fromPassword derives correct key`() {
    val config = PskConfig.fromPassword("myIdentity", "myPassword")
    val expected =
        MessageDigest.getInstance("SHA-256")
            .digest("MYIDENTITY".toByteArray() + "myPassword".toByteArray())
    assertContentEquals(expected, config.pskBytes())
  }

  @Test
  fun `fromPassword uppercases identity for derivation`() {
    val lower = PskConfig.fromPassword("testUser", "pass")
    val upper = PskConfig.fromPassword("TESTUSER", "pass")
    val mixed = PskConfig.fromPassword("TestUser", "pass")
    assertContentEquals(lower.pskBytes(), upper.pskBytes())
    assertContentEquals(lower.pskBytes(), mixed.pskBytes())
  }

  @Test
  fun `fromPassword preserves original identity case`() {
    val config = PskConfig.fromPassword("MyIdentity", "password")
    assertEquals("MyIdentity", config.identity)
  }

  @Test
  fun `fromPassword rejects blank identity`() {
    assertFailsWith<IllegalArgumentException> { PskConfig.fromPassword("", "password") }
    assertFailsWith<IllegalArgumentException> { PskConfig.fromPassword("   ", "password") }
  }

  // --- fromHex ---

  @Test
  fun `fromHex parses valid hex key`() {
    val hex = "a1b2c3d4e5f6" + "0".repeat(52) // 64 hex chars total
    val config = PskConfig.fromHex("id1", hex)
    assertEquals(32, config.pskBytes().size)
    assertEquals(0xa1.toByte(), config.pskBytes()[0])
    assertEquals(0xb2.toByte(), config.pskBytes()[1])
  }

  @Test
  fun `fromHex accepts uppercase hex`() {
    val hex = "A1B2C3D4E5F6" + "0".repeat(52)
    val config = PskConfig.fromHex("id1", hex)
    assertEquals(0xa1.toByte(), config.pskBytes()[0])
  }

  @Test
  fun `fromHex rejects short hex`() {
    assertFailsWith<IllegalArgumentException> { PskConfig.fromHex("id1", "abcd") }
  }

  @Test
  fun `fromHex rejects long hex`() {
    assertFailsWith<IllegalArgumentException> { PskConfig.fromHex("id1", "a".repeat(66)) }
  }

  @Test
  fun `fromHex rejects invalid characters`() {
    assertFailsWith<IllegalArgumentException> { PskConfig.fromHex("id1", "g" + "0".repeat(63)) }
  }

  @Test
  fun `fromHex rejects blank identity`() {
    assertFailsWith<IllegalArgumentException> { PskConfig.fromHex("", "0".repeat(64)) }
  }

  // --- fromKey ---

  @Test
  fun `fromKey accepts valid 32-byte key`() {
    val key = ByteArray(32) { it.toByte() }
    val config = PskConfig.fromKey("id1", key)
    assertContentEquals(key, config.pskBytes())
  }

  @Test
  fun `fromKey defensively copies input`() {
    val key = ByteArray(32) { it.toByte() }
    val config = PskConfig.fromKey("id1", key)
    key[0] = 0xFF.toByte() // mutate original
    assertEquals(0x00.toByte(), config.pskBytes()[0]) // config should be unaffected
  }

  @Test
  fun `pskBytes returns defensive copy`() {
    val config = PskConfig.fromKey("id1", ByteArray(32))
    val bytes1 = config.pskBytes()
    val bytes2 = config.pskBytes()
    assertNotSame(bytes1, bytes2)
    assertContentEquals(bytes1, bytes2)
  }

  @Test
  fun `fromKey rejects wrong size`() {
    assertFailsWith<IllegalArgumentException> { PskConfig.fromKey("id1", ByteArray(16)) }
    assertFailsWith<IllegalArgumentException> { PskConfig.fromKey("id1", ByteArray(64)) }
  }

  @Test
  fun `fromKey rejects blank identity`() {
    assertFailsWith<IllegalArgumentException> { PskConfig.fromKey("", ByteArray(32)) }
  }

  // --- toString / security ---

  @Test
  fun `toString does not leak PSK bytes`() {
    val config = PskConfig.fromKey("id1", ByteArray(32))
    val str = config.toString()
    assertTrue(str.contains("redacted"))
    assertTrue(str.contains("id1"))
    // Ensure no hex dump of zeros
    assertTrue(!str.contains("[0, 0, 0"))
  }

  // --- equals / hashCode ---

  @Test
  fun `equal configs are equal`() {
    val a = PskConfig.fromKey("id1", ByteArray(32) { 1 })
    val b = PskConfig.fromKey("id1", ByteArray(32) { 1 })
    assertEquals(a, b)
    assertEquals(a.hashCode(), b.hashCode())
  }

  @Test
  fun `different keys are not equal`() {
    val a = PskConfig.fromKey("id1", ByteArray(32) { 1 })
    val b = PskConfig.fromKey("id1", ByteArray(32) { 2 })
    assertTrue(a != b)
  }

  // --- hostName ---

  @Test
  fun `hostName defaults to null`() {
    val config = PskConfig.fromPassword("id", "pass")
    assertEquals(null, config.hostName)
  }

  @Test
  fun `hostName is preserved`() {
    val config = PskConfig.fromPassword("id", "pass", hostName = "myhost")
    assertEquals("myhost", config.hostName)
  }
}
