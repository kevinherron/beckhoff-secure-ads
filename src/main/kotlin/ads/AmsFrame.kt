package ads

import io.netty.buffer.ByteBuf

/**
 * Represents an AMS/TCP frame used in the Beckhoff ADS protocol.
 *
 * Each AMS frame consists of:
 * - 6 bytes AMS/TCP Header:
 *     - 2 reserved bytes (always 0)
 *     - 4 bytes for length (total length of header plus data)
 * - 32 bytes AMS Header ([AmsHeader])
 * - Variable length ADS Data payload ([ByteBuf])
 *
 * The frame is used for both sending commands to and receiving responses from ADS devices. The
 * header contains routing and command information, while the data section contains the actual
 * payload specific to the command being executed.
 *
 * @property header the AMS header containing routing and command information.
 * @property data the payload data buffer for this frame.
 */
data class AmsFrame(val header: AmsHeader, val data: ByteBuf)
