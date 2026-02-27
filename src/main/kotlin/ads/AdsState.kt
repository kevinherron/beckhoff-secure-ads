package ads

enum class AdsState(val value: UShort) {
  /** ADS State is Invalid / Uninitialized */
  INVALID(0u),

  /** Idle */
  IDLE(1u),

  /** Reset */
  RESET(2u),

  /** Initialize */
  INIT(3u),

  /** Start */
  START(4u),

  /** Run */
  RUN(5u),

  /** Stop */
  STOP(6u),

  /** Save Configuration */
  SAVE_CONFIG(7u),

  /** Load Configuration */
  LOAD_CONFIG(8u),

  /** Power failure */
  POWER_FAILURE(9u),

  /** Power Good */
  POWER_GOOD(10u),

  /** Error */
  ERROR(11u),

  /** Shutdown */
  SHUTDOWN(12u),

  /** Suspend */
  SUSPEND(13u),

  /** Resume */
  RESUME(14u),

  /** Config (System is in config mode) */
  CONFIG(15u),

  /** Reconfig (System should restart in config mode) */
  RECONFIG(16u),

  /** Stopping */
  STOPPING(17u),

  /** Incompatible */
  INCOMPATIBLE(18u),

  /** Exception */
  EXCEPTION(19u);

  companion object {

    private val values = entries.associateBy(AdsState::value)

    /** Look up an [AdsState] by its [value]. */
    fun fromValue(value: UShort): AdsState? = values[value]

    /** Look up an [AdsState] by its [value]. */
    fun fromValue(value: Int): AdsState? = fromValue(value.toUShort())
  }
}
