package ads.client

import java.nio.file.Path
import java.security.MessageDigest

/**
 * Base sealed interface for all Secure ADS configuration variants.
 *
 * Implementations include certificate-based modes ([SelfSignedConfig], [SharedCaConfig]) and
 * pre-shared key mode ([PskConfig]).
 */
sealed interface SecureAdsConfig {
  val hostName: String?
}

/**
 * Sealed interface for certificate-based Secure ADS configurations that require a PKCS12 keystore.
 */
sealed interface CertificateConfig : SecureAdsConfig {
  val keyStorePath: Path
  val keyStorePassword: String
  val keyStoreAlias: String
  val keyStoreAliasPassword: String
}

/** Self-signed certificate configuration for Secure ADS. */
data class SelfSignedConfig(
    override val keyStorePath: Path,
    override val keyStorePassword: String,
    override val keyStoreAlias: String,
    override val keyStoreAliasPassword: String,
    override val hostName: String? = null,
    val credentials: Pair<String, String>? = null,
) : CertificateConfig

/** Shared CA certificate configuration for Secure ADS. */
data class SharedCaConfig(
    val caCertPath: Path,
    override val keyStorePath: Path,
    override val keyStorePassword: String,
    override val keyStoreAlias: String,
    override val keyStoreAliasPassword: String,
    override val hostName: String? = null,
) : CertificateConfig

/**
 * Pre-shared key (PSK) configuration for Secure ADS.
 *
 * The PSK is a 32-byte (256-bit) key. Use the companion factory methods to create instances:
 * - [fromPassword] — derives the key via `SHA-256(UPPER(identity) + password)`
 * - [fromHex] — parses a 64-character hex string
 * - [fromKey] — uses raw key bytes directly
 *
 * The [identity] is the PSK identity string configured in TwinCAT's `StaticRoutes.xml`.
 *
 * Security notes:
 * - PSK bytes are defensively copied on construction and on access via [pskBytes].
 * - [toString] redacts the key material.
 * - [equals] and [hashCode] use content-based comparison for the key.
 */
class PskConfig
private constructor(
    /** The PSK identity string. Must be non-blank. */
    val identity: String,
    private val psk: ByteArray,
    override val hostName: String? = null,
) : SecureAdsConfig {

  init {
    require(identity.isNotBlank()) { "PSK identity must be non-blank" }
    require(psk.size == PSK_LENGTH) {
      "PSK must be exactly $PSK_LENGTH bytes (${PSK_LENGTH * 8} bits), got ${psk.size} bytes"
    }
  }

  /** Returns a defensive copy of the PSK bytes. */
  fun pskBytes(): ByteArray = psk.copyOf()

  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (other !is PskConfig) return false
    return identity == other.identity && psk.contentEquals(other.psk) && hostName == other.hostName
  }

  override fun hashCode(): Int {
    var result = identity.hashCode()
    result = 31 * result + psk.contentHashCode()
    result = 31 * result + (hostName?.hashCode() ?: 0)
    return result
  }

  override fun toString(): String {
    return "PskConfig[identity=$identity, psk=<redacted>, hostName=$hostName]"
  }

  companion object {
    /** Expected PSK length in bytes (SHA-256 output). */
    const val PSK_LENGTH: Int = 32

    /**
     * Derives a PSK from [identity] and [password] using TwinCAT's default derivation:
     * `SHA-256(UPPER(identity) + password)`.
     *
     * TwinCAT defaults to `IdentityCaseSensitive="false"`, which uppercases the identity before
     * concatenation.
     */
    fun fromPassword(
        identity: String,
        password: String,
        hostName: String? = null,
    ): PskConfig {
      require(identity.isNotBlank()) { "PSK identity must be non-blank" }

      val input = identity.uppercase() + password
      val digest = MessageDigest.getInstance("SHA-256")
      val key = digest.digest(input.toByteArray(Charsets.UTF_8))

      return PskConfig(identity = identity, psk = key, hostName = hostName)
    }

    /**
     * Creates a [PskConfig] from a 64-character hexadecimal key string.
     *
     * @throws IllegalArgumentException if [hexKey] is not exactly 64 hex characters.
     */
    fun fromHex(
        identity: String,
        hexKey: String,
        hostName: String? = null,
    ): PskConfig {
      require(identity.isNotBlank()) { "PSK identity must be non-blank" }
      require(hexKey.length == PSK_LENGTH * 2) {
        "hex key must be exactly ${PSK_LENGTH * 2} characters, got ${hexKey.length}"
      }
      require(hexKey.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) {
        "hex key contains invalid characters"
      }

      val key = hexKey.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

      return PskConfig(identity = identity, psk = key, hostName = hostName)
    }

    /**
     * Creates a [PskConfig] from raw key bytes.
     *
     * @throws IllegalArgumentException if [keyBytes] is not exactly 32 bytes.
     */
    fun fromKey(
        identity: String,
        keyBytes: ByteArray,
        hostName: String? = null,
    ): PskConfig {
      return PskConfig(identity = identity, psk = keyBytes.copyOf(), hostName = hostName)
    }
  }
}
