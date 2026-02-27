package ads.commands

import ads.AdsErrorCode
import io.netty.buffer.ByteBuf

data object AdsReadDeviceInfoRequest

/**
 * Response containing name and version information from an ADS device.
 *
 * @property result the [AdsErrorCode].
 * @property majorVersion the major version number.
 * @property minorVersion the minor version number.
 * @property version the build number.
 * @property deviceName the name of the ADS device (max 16 characters).
 */
data class AdsReadDeviceInfoResponse(
    val result: AdsErrorCode,
    val majorVersion: UByte,
    val minorVersion: UByte,
    val version: UShort,
    val deviceName: String,
) {

  object Serde {

    /** Encode [response] into the provided [buffer]. */
    fun encode(response: AdsReadDeviceInfoResponse, buffer: ByteBuf) {
      buffer.writeIntLE(response.result.code.toInt())
      buffer.writeByte(response.majorVersion.toInt())
      buffer.writeByte(response.minorVersion.toInt())
      buffer.writeShortLE(response.version.toInt())

      // Device name is written as a fixed 16-byte field:
      // - If the name is shorter than 16 characters, bytes are padded with null
      // - If the name is exactly 16 characters, no null terminator is added
      // - If the name exceeds 16 characters, it is truncated to 16 characters
      val deviceNameBytes = response.deviceName.toByteArray(Charsets.UTF_8)
      val paddedBytes = ByteArray(16)
      val copyLength = minOf(deviceNameBytes.size, 16)
      System.arraycopy(deviceNameBytes, 0, paddedBytes, 0, copyLength)
      buffer.writeBytes(paddedBytes)
    }

    /** Decode an [AdsReadDeviceInfoResponse] from the provided [buffer]. */
    fun decode(buffer: ByteBuf): AdsReadDeviceInfoResponse {
      val result: AdsErrorCode = AdsErrorCode.Companion.from(buffer.readUnsignedIntLE().toUInt())
      val majorVersion: UByte = buffer.readUnsignedByte().toUByte()
      val minorVersion: UByte = buffer.readUnsignedByte().toUByte()
      val version: UShort = buffer.readUnsignedShortLE().toUShort()
      val deviceNameBytes = ByteArray(16)
      buffer.readBytes(deviceNameBytes)
      val deviceName: String = deviceNameBytes.toString(Charsets.UTF_8).trimEnd('\u0000')

      return AdsReadDeviceInfoResponse(
          result,
          majorVersion,
          minorVersion,
          version,
          deviceName,
      )
    }
  }
}
