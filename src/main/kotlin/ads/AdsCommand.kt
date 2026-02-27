package ads

enum class AdsCommand(val id: UShort) {
  /** Invalid command. */
  INVALID(0x0000u),

  /** Reads the name and version number of the ADS device. */
  ADS_READ_DEVICE_INFO(0x0001u),

  /** Reads data from an ADS device. */
  ADS_READ(0x0002u),

  /** Writes data to an ADS device. */
  ADS_WRITE(0x0003u),

  /** Reads the ADS status and device status of an ADS device. */
  ADS_READ_STATE(0x0004u),

  /** Changes the ADS status and device status of an ADS device. */
  ADS_WRITE_CONTROL(0x0005u),

  /** Creates a notification in an ADS device. */
  ADS_ADD_DEVICE_NOTIFICATION(0x0006u),

  /** Deletes a previously defined notification in an ADS device. */
  ADS_DELETE_DEVICE_NOTIFICATION(0x0007u),

  /** Sends device notification data to an ADS client. */
  ADS_DEVICE_NOTIFICATION(0x0008u),

  /** Writes data to an ADS device and additionally reads data from the ADS device. */
  ADS_READ_WRITE(0x0009u);

  companion object {

    private val ids = entries.associateBy(AdsCommand::id)

    /** Look up an [AdsCommand] by its [id]. */
    fun fromId(id: UShort): AdsCommand? = ids[id]

    /** Look up an [AdsCommand] by its [id]. */
    fun fromId(id: Int): AdsCommand? = fromId(id.toUShort())
  }
}
