import java.nio.file.Path

object Config {
  // Network - set to match your environment
  const val TARGET_HOST = "172.16.96.129"
  const val TARGET_PORT: UShort = 8016u

  // AMS - set to match your environment
  const val SOURCE_AMS_NET_ID = "172.16.96.1.1.1"
  const val SOURCE_AMS_PORT: UShort = 32768u
  const val TARGET_AMS_NET_ID = "172.16.96.129.1.1"
  const val TARGET_AMS_PORT: UShort = 851u

  // Credentials (SSC AddRoute)
  val USERNAME: String by lazy { System.getenv("ADS_USERNAME") ?: error("ADS_USERNAME not set") }
  val PASSWORD: String by lazy { System.getenv("ADS_PASSWORD") ?: error("ADS_PASSWORD not set") }

  // PSK credentials
  val PSK_IDENTITY: String by lazy {
    System.getenv("ADS_PSK_IDENTITY") ?: error("ADS_PSK_IDENTITY not set")
  }
  val PSK_PASSWORD: String by lazy {
    System.getenv("ADS_PSK_PASSWORD") ?: error("ADS_PSK_PASSWORD not set")
  }

  // Keystore
  const val KEYSTORE_ALIAS = "ads-client"
  const val KEYSTORE_PASSWORD = "password"

  // PKI paths - SCA
  val SCA_CA_CERT_PATH: Path = Path.of("pki/sca/ca/rootCA.pem")
  val SCA_KEYSTORE_PATH: Path = Path.of("pki/sca/client/client.p12")

  // PKI paths - SSC
  val SSC_KEYSTORE_PATH: Path = Path.of("pki/ssc/client-keystore.p12")
}
