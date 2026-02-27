import ads.AmsNetId
import ads.TlsConnectInfo
import ads.TlsConnectInfo.Flag
import io.netty.handler.ssl.SslContext
import io.netty.handler.ssl.SslContextBuilder
import io.netty.handler.ssl.SupportedCipherSuiteFilter
import io.netty.handler.ssl.util.InsecureTrustManagerFactory
import java.io.FileInputStream
import java.net.InetAddress
import java.security.KeyStore

fun main() {
  val sslContext = buildSslContext()
  val request = buildTlsConnectInfoRequest()

  connectAndAddRoute(sslContext, request)
}

// region Helper Functions

private fun buildSslContext(): SslContext {
  val keyStore = KeyStore.getInstance("PKCS12")
  FileInputStream(Config.SSC_KEYSTORE_PATH.toFile()).use { fis ->
    keyStore.load(fis, Config.KEYSTORE_PASSWORD.toCharArray())
  }
  println("Loaded client keystore from ${Config.SSC_KEYSTORE_PATH}")

  val key =
      keyStore.getKey(Config.KEYSTORE_ALIAS, Config.KEYSTORE_PASSWORD.toCharArray())
          as java.security.PrivateKey
  val cert = keyStore.getCertificate(Config.KEYSTORE_ALIAS) as java.security.cert.X509Certificate

  return SslContextBuilder.forClient()
      .keyManager(key, cert)
      .trustManager(InsecureTrustManagerFactory.INSTANCE)
      .ciphers(TLS_CIPHER_SUITES, SupportedCipherSuiteFilter.INSTANCE)
      .protocols(*TLS_PROTOCOLS)
      .endpointIdentificationAlgorithm(null)
      .build()
}

private fun buildTlsConnectInfoRequest(): TlsConnectInfo {
  val userBytes = Config.USERNAME.toByteArray(TlsConnectInfo.CHARSET)
  val passwordBytes = Config.PASSWORD.toByteArray(TlsConnectInfo.CHARSET)
  val length = TlsConnectInfo.Serde.BASE_SIZE + userBytes.size + passwordBytes.size

  return TlsConnectInfo(
      length = length.toUShort(),
      flags = setOf(Flag.ADD_REMOTE, Flag.SELF_SIGNED, Flag.IP_ADDR, Flag.IGNORE_CN),
      version = 1u,
      error = TlsConnectInfo.TlsError.NO_ERROR,
      amsNetId = AmsNetId(Config.SOURCE_AMS_NET_ID),
      reserved = ByteArray(18),
      hostName = InetAddress.getLocalHost().hostName,
      credentials = Pair(Config.USERNAME, Config.PASSWORD),
  )
}

// endregion
