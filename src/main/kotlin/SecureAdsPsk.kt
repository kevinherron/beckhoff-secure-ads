import ads.AmsNetId
import ads.AmsPort
import ads.Shared
import ads.client.AdsClient
import ads.client.AdsClientConfig
import ads.client.PskConfig
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
  val config =
      AdsClientConfig(
          hostname = Config.TARGET_HOST,
          port = Config.TARGET_PORT,
          targetNetId = AmsNetId(Config.TARGET_AMS_NET_ID),
          targetPort = AmsPort(Config.TARGET_AMS_PORT),
          sourceNetId = AmsNetId(Config.SOURCE_AMS_NET_ID),
          sourcePort = AmsPort(Config.SOURCE_AMS_PORT),
          secureAdsConfig =
              PskConfig.fromPassword(
                  identity = Config.PSK_IDENTITY,
                  password = Config.PSK_PASSWORD,
              ),
      )

  val client = AdsClient(config)

  try {
    println("Connecting to ${Config.TARGET_HOST}:${Config.TARGET_PORT} (Secure ADS / PSK)...")
    client.connect().getOrThrow()
    println("Connected!")

    val deviceInfo = client.readDeviceInfo().getOrThrow()
    println("$deviceInfo")

    val state = client.readState().getOrThrow()
    println("$state")
  } finally {
    client.disconnect()
    Shared.releaseSharedResources()
  }
}
