plugins {
  kotlin("jvm") version "2.3.0"
  id("com.diffplug.spotless") version "8.2.1"
}

group = "com.kevinherron.ads"

version = "1.0-SNAPSHOT"

repositories { mavenCentral() }

dependencies {
  implementation(kotlin("stdlib"))
  implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.9.0")

  implementation("io.netty:netty-all:4.2.10.Final")
  implementation("org.bouncycastle:bctls-jdk18on:1.80")
  implementation("ch.qos.logback:logback-classic:1.5.32")

  testImplementation(kotlin("test"))
}

kotlin { jvmToolchain(17) }

tasks.test { useJUnitPlatform() }

fun registerRunTask(taskName: String, mainClassName: String, taskDescription: String) {
  tasks.register<JavaExec>(taskName) {
    group = "runnable example"
    description = taskDescription
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set(mainClassName)
  }
}

registerRunTask(
    "runSecureAdsSelfSigned",
    "SecureAdsSelfSignedKt",
    "Run Secure ADS client (self-signed cert mode)",
)

registerRunTask(
    "runSecureAdsSharedCa",
    "SecureAdsSharedCaKt",
    "Run Secure ADS client (CA-signed cert mode)",
)

registerRunTask(
    "runAddRouteSelfSigned",
    "AddRouteSelfSignedKt",
    "Register ADS route (self-signed cert mode)",
)

registerRunTask(
    "runSecureAdsPsk",
    "SecureAdsPskKt",
    "Run Secure ADS client (PSK mode)",
)


spotless { kotlin { ktfmt() } }
