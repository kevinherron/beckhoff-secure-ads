package ads.commands

import ads.AdsErrorCode
import io.netty.buffer.ByteBuf

object AdsReadStateRequest

data class AdsReadStateResponse(
    val result: AdsErrorCode,
    val adsState: UShort,
    val deviceState: UShort,
) {

  object Serde {

    /** Encode [response] into the provided [buffer]. */
    fun encode(response: AdsReadStateResponse, buffer: ByteBuf) {
      buffer.writeIntLE(response.result.code.toInt())
      buffer.writeShortLE(response.adsState.toInt())
      buffer.writeShortLE(response.deviceState.toInt())
    }

    /** Decode an [AdsReadStateResponse] from the provided [buffer]. */
    fun decode(buffer: ByteBuf): AdsReadStateResponse {
      val result: AdsErrorCode = AdsErrorCode.Companion.from(buffer.readUnsignedIntLE().toUInt())
      val adsState: UShort = buffer.readUnsignedShortLE().toUShort()
      val deviceState: UShort = buffer.readUnsignedShortLE().toUShort()

      return AdsReadStateResponse(result, adsState, deviceState)
    }
  }
}
