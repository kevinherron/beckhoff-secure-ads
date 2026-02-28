package ads.client

import ads.AmsNetId
import ads.TlsConnectInfo
import io.netty.handler.ssl.SslContext
import io.netty.handler.ssl.SslContextBuilder
import io.netty.handler.ssl.SupportedCipherSuiteFilter
import io.netty.handler.ssl.util.InsecureTrustManagerFactory
import java.io.FileInputStream
import java.net.InetAddress
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.X509Certificate

private val CIPHER_SUITES =
    listOf(
        "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
        "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
        "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    )

internal val PROTOCOLS = arrayOf("TLSv1.2")

internal fun buildSslContext(config: CertificateConfig): SslContext {
  val keyStore = KeyStore.getInstance("PKCS12")
  FileInputStream(config.keyStorePath.toFile()).use { fis ->
    keyStore.load(fis, config.keyStorePassword.toCharArray())
  }

  val key =
      keyStore.getKey(
          config.keyStoreAlias,
          config.keyStoreAliasPassword.toCharArray(),
      ) as PrivateKey

  val cert = keyStore.getCertificate(config.keyStoreAlias) as X509Certificate

  val builder =
      SslContextBuilder.forClient()
          .keyManager(key, cert)
          .apply {
            when (config) {
              is SelfSignedConfig -> trustManager(InsecureTrustManagerFactory.INSTANCE)
              is SharedCaConfig -> trustManager(config.caCertPath.toFile())
            }
          }
          .ciphers(CIPHER_SUITES, SupportedCipherSuiteFilter.INSTANCE)
          .protocols(*PROTOCOLS)
          .endpointIdentificationAlgorithm(null)

  return builder.build()
}

internal fun buildTlsConnectInfoRequest(
    config: SecureAdsConfig,
    sourceNetId: AmsNetId,
): TlsConnectInfo {
  val hostName = config.hostName ?: InetAddress.getLocalHost().hostName

  val credentials: Pair<String, String>?
  val flags: Set<TlsConnectInfo.Flag>

  when (config) {
    is SelfSignedConfig -> {
      credentials = config.credentials
      flags = setOf(TlsConnectInfo.Flag.SELF_SIGNED)
    }
    is SharedCaConfig -> {
      credentials = null
      flags = emptySet()
    }
    is PskConfig -> {
      credentials = null
      flags = emptySet()
    }
  }

  val baseSize = TlsConnectInfo.Serde.BASE_SIZE
  val userBytes = credentials?.first?.toByteArray(TlsConnectInfo.CHARSET)
  val passwordBytes = credentials?.second?.toByteArray(TlsConnectInfo.CHARSET)
  val length = baseSize + (userBytes?.size ?: 0) + (passwordBytes?.size ?: 0)

  return TlsConnectInfo(
      length = length.toUShort(),
      flags = flags,
      version = 1u,
      error = TlsConnectInfo.TlsError.NO_ERROR,
      amsNetId = sourceNetId,
      reserved = ByteArray(18),
      hostName = hostName,
      credentials = credentials,
  )
}
