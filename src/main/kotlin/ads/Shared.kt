package ads

import io.netty.channel.MultiThreadIoEventLoopGroup
import io.netty.channel.nio.NioIoHandler
import io.netty.util.HashedWheelTimer
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ThreadFactory
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong
import org.slf4j.LoggerFactory

object Shared {

  private val logger = LoggerFactory.getLogger(javaClass)

  @Volatile private var wheelTimer: HashedWheelTimer? = null

  @Volatile private var eventLoopGroup: MultiThreadIoEventLoopGroup? = null

  @Volatile private var executor: ExecutorService? = null

  @Volatile private var scheduledExecutor: ScheduledExecutorService? = null

  @Synchronized
  fun sharedWheelTimer(): HashedWheelTimer {
    if (wheelTimer == null) {
      wheelTimer = HashedWheelTimer(daemonThreadFactory("ads-wheel-timer"))
    }
    return wheelTimer!!
  }

  @Synchronized
  fun sharedEventLoopGroup(): MultiThreadIoEventLoopGroup {
    if (eventLoopGroup == null) {
      eventLoopGroup =
          MultiThreadIoEventLoopGroup(
              1,
              daemonThreadFactory("ads-event-loop"),
              NioIoHandler.newFactory(),
          )
    }
    return eventLoopGroup!!
  }

  @Synchronized
  fun sharedExecutor(): ExecutorService {
    if (executor == null) {
      executor = Executors.newCachedThreadPool(daemonThreadFactory("ads-executor"))
    }
    return executor!!
  }

  @Synchronized
  fun sharedScheduledExecutor(): ScheduledExecutorService {
    if (scheduledExecutor == null) {
      scheduledExecutor =
          Executors.newSingleThreadScheduledExecutor(daemonThreadFactory("ads-scheduled-executor"))
    }
    return scheduledExecutor!!
  }

  /** Release shared resources with a default timeout of 5 seconds. */
  fun releaseSharedResources() {
    releaseSharedResources(5, TimeUnit.SECONDS)
  }

  /**
   * Release shared resources with the specified timeout.
   *
   * @param timeout the timeout value
   * @param unit the timeout unit
   */
  @Synchronized
  fun releaseSharedResources(timeout: Long, unit: TimeUnit) {
    wheelTimer?.let { timer ->
      try {
        timer.stop()
        wheelTimer = null
      } catch (e: Exception) {
        logger.warn("Error stopping HashedWheelTimer", e)
      }
    }

    eventLoopGroup?.let { group ->
      try {
        val future = group.shutdownGracefully(0, timeout, unit)
        if (!future.await(timeout, unit)) {
          logger.warn("EventLoopGroup shutdown timed out after {} {}", timeout, unit)
        }
        eventLoopGroup = null
      } catch (e: InterruptedException) {
        logger.warn("Interrupted while shutting down EventLoopGroup", e)
        Thread.currentThread().interrupt()
      } catch (e: Exception) {
        logger.warn("Error shutting down EventLoopGroup", e)
      }
    }

    executor?.let { exec ->
      try {
        exec.shutdown()
        if (!exec.awaitTermination(timeout, unit)) {
          logger.warn("Executor shutdown timed out after {} {}, forcing shutdown", timeout, unit)
          exec.shutdownNow()
        }
        executor = null
      } catch (e: InterruptedException) {
        logger.warn("Interrupted while shutting down Executor", e)
        exec.shutdownNow()
        Thread.currentThread().interrupt()
      } catch (e: Exception) {
        logger.warn("Error shutting down Executor", e)
      }
    }

    scheduledExecutor?.let { exec ->
      try {
        exec.shutdown()
        if (!exec.awaitTermination(timeout, unit)) {
          logger.warn(
              "ScheduledExecutor shutdown timed out after {} {}, forcing shutdown",
              timeout,
              unit,
          )
          exec.shutdownNow()
        }
        scheduledExecutor = null
      } catch (e: InterruptedException) {
        logger.warn("Interrupted while shutting down ScheduledExecutor", e)
        exec.shutdownNow()
        Thread.currentThread().interrupt()
      } catch (e: Exception) {
        logger.warn("Error shutting down ScheduledExecutor", e)
      }
    }
  }

  private fun daemonThreadFactory(namePrefix: String): ThreadFactory {
    return ThreadFactory { runnable ->
      val threadNumber = THREAD_NUMBER.getAndIncrement()
      Thread(runnable, "$namePrefix-$threadNumber").apply {
        isDaemon = true
        uncaughtExceptionHandler =
            Thread.UncaughtExceptionHandler { t, e ->
              logger.error("Uncaught exception on thread '{}'", t.name, e)
            }
      }
    }
  }

  private val THREAD_NUMBER = AtomicLong(0L)
}
