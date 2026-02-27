package ads.client

import ads.AmsNetId
import ads.AmsPort
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds

data class AdsClientConfig(
    val hostname: String,
    val port: UShort = 48898u,
    val targetNetId: AmsNetId,
    val targetPort: AmsPort,
    val sourceNetId: AmsNetId,
    val sourcePort: AmsPort,
    val connectTimeout: Duration = 2000.milliseconds,
    val requestTimeout: Duration = 2000.milliseconds,
    val secureAdsConfig: SecureAdsConfig? = null,
)
