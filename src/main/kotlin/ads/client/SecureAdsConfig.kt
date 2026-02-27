package ads.client

import java.nio.file.Path

sealed interface SecureAdsConfig {
  val keyStorePath: Path
  val keyStorePassword: String
  val keyStoreAlias: String
  val keyStoreAliasPassword: String
  val hostName: String?

  data class SelfSignedConfig(
      override val keyStorePath: Path,
      override val keyStorePassword: String,
      override val keyStoreAlias: String,
      override val keyStoreAliasPassword: String,
      override val hostName: String? = null,
      val credentials: Pair<String, String>? = null,
  ) : SecureAdsConfig

  data class SharedCaConfig(
      val caCertPath: Path,
      override val keyStorePath: Path,
      override val keyStorePassword: String,
      override val keyStoreAlias: String,
      override val keyStoreAliasPassword: String,
      override val hostName: String? = null,
  ) : SecureAdsConfig
}
