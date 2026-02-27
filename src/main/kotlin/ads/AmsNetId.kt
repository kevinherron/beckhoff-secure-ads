package ads

/**
 * The AMSNetId is a 6-byte logical address used to identify a transmitter or receiver in the ADS
 * Protocol.
 *
 * @param netId the byte array representing the AMSNetId, which must be exactly 6 bytes long.
 */
@JvmInline
value class AmsNetId(val netId: ByteArray) {

  init {
    require(netId.size == NET_ID_LENGTH) { "AmsNetId must be exactly $NET_ID_LENGTH bytes long." }
  }

  override fun toString(): String = netId.joinToString(".") { (it.toInt() and 0xFF).toString() }

  companion object {

    const val NET_ID_LENGTH: Int = 6

    /**
     * Creates an AmsNetId from a string representation.
     *
     * The string must consist of 6 parts separated by dots, where each part is a number between 0
     * and 255 (inclusive).
     *
     * @param netId the string representation of the AMS Net ID.
     * @return an instance of AmsNetId.
     * @throws IllegalArgumentException if the string does not conform to the expected format.
     */
    operator fun invoke(netId: String): AmsNetId {
      val parts = netId.split('.')
      require(parts.size == NET_ID_LENGTH) {
        "AmsNetId string must have exactly $NET_ID_LENGTH parts separated by '.'"
      }
      val byteArray =
          ByteArray(NET_ID_LENGTH) { i ->
            val part =
                parts[i].toIntOrNull()
                    ?: throw IllegalArgumentException("Invalid number in AmsNetId: '${parts[i]}'")
            require(part in 0..255) {
              "Each part of AmsNetId must be between 0 and 255. Found: $part"
            }
            part.toByte()
          }

      return AmsNetId(byteArray)
    }
  }
}
