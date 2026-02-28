# Beckhoff Secure ADS

Beckhoff's [Secure ADS](https://infosys.beckhoff.com/content/1033/tc3_grundlagen/6798091787.html?id=7122633824373499954)
adds TLS 1.2 encryption to ADS communications on TCP port 8016, complementing
standard unencrypted ADS (TCP 48898) and UDP route management (UDP 48899). It
was introduced in TwinCAT 3.1 Build 4024.0.

In a typical TwinCAT setup, Secure ADS runs between TwinCAT routers on each
machine. The routers handle the TLS tunnel and `TlsConnectInfo` exchange
transparently — existing ADS applications continue using the local router as
before, unaware that traffic between routers is now encrypted. This
documentation is primarily relevant for applications or libraries that
communicate directly with a PLC over TCP without a local TwinCAT router or
that implement their own ADS routing.

The official documentation covers TLS setup and certificate management but
leaves the application-layer handshake protocol undocumented. This repository
fills that gap: it documents the `TlsConnectInfo` structure that is exchanged
immediately after the TLS handshake, explains its dual role in route
registration and established-route communication, and describes the removal of
the AMS/TCP framing header inside the TLS tunnel. A minimal Kotlin/Netty ADS
client and four runnable examples demonstrate both Self-Signed Certificate (SSC)
and Shared CA (SCA) modes.

---

## The Secure ADS Connection Protocol

Every Secure ADS connection follows the same sequence:

```
1. TCP connect to port 8016
2. TLS 1.2 handshake (mTLS - both sides present certificates)
3. TlsConnectInfo request  (client -> server, inside TLS tunnel)
4. TlsConnectInfo response (server -> client, inside TLS tunnel)
5. AMS/ADS frames (inside TLS tunnel)
```

There are two key differences from standard ADS (port 48898):

1. **The TlsConnectInfo exchange** -- an application-layer handshake that occurs
   once per connection, immediately after TLS completes.
2. **No AMS/TCP header** – inside the TLS tunnel, the 6-byte AMS/TCP framing
   header is omitted. Only raw AMS headers and data are sent. The TLS record layer
   provides the framing that the AMS/TCP header normally provides.

### AMS/TCP Header Omission

In standard ADS, every AMS frame is prefixed with a 6-byte header:

```
+------------------+------------------------------+
| Reserved (2)     | AMS Data Length (4, LE)      |
+------------------+------------------------------+
```

In Secure ADS, this header is **omitted**. The receiver uses the `length` field
from the 32-byte AMS header (at offset 24) to determine how many data bytes
follow the header. The PLC will reject frames that include the AMS/TCP header
inside the TLS tunnel.

---

## TlsConnectInfo

`TlsConnectInfo` is the only application-layer handshake in Secure ADS. It is a
single request/response exchange sent on every connection. Its role depends on
the authentication mode:

- **SSC mode** requires an explicit route addition step on first connection: the
  `AddRemote` flag is set and credentials (username/password) are included. On
  success, the PLC persists the route. Subsequent connections omit `AddRemote`
  and credentials — authentication relies on mTLS + certificate fingerprint
  pinning from the initial registration.
- **SCA mode** does not require explicit route addition. The CA-signed
  certificate is sufficient authentication. Every connection sends a minimal
  `TlsConnectInfo` with no `AddRemote` flag and no credentials.
- **PSK mode** does not require explicit route addition. The PSK identity entry
  in `StaticRoutes.xml` acts as the route. Every connection sends a minimal
  `TlsConnectInfo` with no flags and no credentials.

### Wire Format

The base structure is 64 bytes. When credentials are included (SSC route
addition), the username and password are appended after the base, making the
total length up to 512 bytes.

```
  Byte     0         1         2         3         4         5         6         7
      +---------+---------+---------+---------+---------+---------+---------+---------+
   0  | Total Length (LE) |    Flags (LE)     | Version |  Error  |     AmsNetId      |
      +---------+---------+---------+---------+---------+---------+---------+---------+
   8  |          AmsNetId (continued)         | UserLen | PwdLen  |     Reserved      |
      +---------+---------+---------+---------+---------+---------+---------+---------+
  16  |                              Reserved (continued)                             |
      +---------+---------+---------+---------+---------+---------+---------+---------+
  24  |                              Reserved (continued)                             |
      +---------+---------+---------+---------+---------+---------+---------+---------+
  32  |                                                                               |
      +                                                                               +
  40  |                                                                               |
      +                       HostName (32 bytes, null-padded)                        +
  48  |                                                                               |
      +                                                                               +
  56  |                                                                               |
      +---------+---------+---------+---------+---------+---------+---------+---------+
      |                                                                               |
 64+  |                           User string (var length)                            |
      |                                                                               |
      +---------+---------+---------+---------+---------+---------+---------+---------+
      |                                                                               |
 64+u |                         Password string (var length)                          |
      |                                                                               |
      +---------+---------+---------+---------+---------+---------+---------+---------+
```

| Offset | Size | Field                                              |
|--------|------|----------------------------------------------------|
| 0-1    | 2    | Total length (uint16 LE)                           |
| 2-3    | 2    | Flags (uint16 LE, see below)                       |
| 4      | 1    | Version (always 1)                                 |
| 5      | 1    | Error code (see below)                             |
| 6-11   | 6    | AMS Net ID                                         |
| 12     | 1    | Username string length (0 if no credentials)       |
| 13     | 1    | Password string length (0 if no credentials)       |
| 14-31  | 18   | Reserved (zero-filled)                             |
| 32-63  | 32   | Hostname (null-padded, Windows-1252 encoded)       |
| 64+    | var  | Username string (Windows-1252, only if length > 0) |
| 64+u   | var  | Password string (Windows-1252, only if length > 0) |

**String encoding:** All strings use the system ANSI code page (Windows-1252 on
Western systems), not UTF-8. The hostname field is fixed at 32 bytes,
null-padded. Credentials are variable-length and treated as an all-or-nothing
pair: if either is null, both lengths are set to 0 and neither string is
appended.

### Flags

| Flag         | Value | Description                                        |
|--------------|-------|----------------------------------------------------|
| `Response`   | 0x01  | Set in server responses                            |
| `AmsAllowed` | 0x02  | AMS communication permitted (response only)        |
| `ServerInfo` | 0x04  | Store only fingerprint, not peer IP                |
| `OwnFile`    | 0x08  | Store in separate file (not StaticRoutes.xml)      |
| `SelfSigned` | 0x10  | Self-signed certificate mode                       |
| `IpAddr`     | 0x20  | Destination identified by IP address (vs hostname) |
| `IgnoreCn`   | 0x40  | Skip Common Name verification                      |
| `AddRemote`  | 0x80  | Add route to remote peer                           |

**Note on `IpAddr` and `IgnoreCn`:** These flags are environment-dependent, not
always required. If DNS is configured and hostnames resolve reliably, `IpAddr`
may be omitted (the route will be identified by hostname instead of IP).
Similarly, if certificates are generated with the correct hostname in the Common
Name (CN) field, `IgnoreCn` is unnecessary. The examples in this repository set
both flags for convenience, but production deployments should use only the flags
appropriate for their environment.

### Response Error Codes

The server always responds with exactly 64 bytes (no credentials). The `Response`
flag (0x01) is set, and the server's AMS Net ID is in the NetId field.

| Error         | Value | Description                                               |
|---------------|-------|-----------------------------------------------------------|
| `NoError`     | 0     | Connection accepted                                       |
| `Version`     | 1     | Unknown TLS version                                       |
| `CnMismatch`  | 2     | Certificate CN doesn't match expected value               |
| `UnknownCert` | 3     | Certificate not trusted / unknown                         |
| `UnknownUser` | 4     | Authentication failed (bad credentials or unknown client) |

---

## Authentication Modes

Beckhoff Secure ADS supports three authentication modes:

- **SSC** – Self-Signed Certificate
- **SCA** – Shared CA (both peers trust certificates issued by a shared CA)
- **PSK** – Pre-Shared Key (TLS-PSK with identity and derived key)

### SSC Mode (Self-Signed Certificate)

Each side generates its own self-signed certificate. Trust is established via
TOFU (Trust On First Use) with SHA-256 certificate fingerprint pinning.

**Route addition:** The client sends the `AddRemote`, and `SelfSigned` flags
with a username and password appended after the 64-byte base. The server
checks credentials against the local user database and stores the client's
certificate fingerprint for future connections. The `IpAddr` and `IgnoreCn`
flags are environment-dependent (see note above); the examples here use
`AddRemote | SelfSigned | IpAddr | IgnoreCn` (0xF0).

```
Engineering PC                                PLC:8016
       |                                             |
       |---- TCP connect --------------------------->|
       |                                             |
       |<=== TLS 1.2 Handshake (mTLS) ==============>|
       |  (self-signed certs, CN mismatch tolerated) |
       |                                             |
       |  TlsConnectInfo Request (64+ bytes)         |
       |  flags=AddRemote|SelfSigned                 |
       |        [|IpAddr] [|IgnoreCn]                |
       |  netId=client AmsNetId                      |
       |  hostname=client machine name               |
       |  user=<username>, pwd=<password>            |
       |-------------------------------------------->|
       |                                             |
       |  Server checks credentials, stores cert     |
       |  fingerprint + route                        |
       |                                             |
       |  TlsConnectInfo Response (64 bytes)         |
       |  flags=Response(0x01), error=NoError(0)     |
       |  netId=server AmsNetId                      |
       |<--------------------------------------------|
       |                                             |
       |<==== AMS frames (no AMS/TCP header) =======>|
```

**Established route:** The client sends flags `SelfSigned` (0x10), no
credentials, exactly 64 bytes. Authentication relies on mTLS + fingerprint
match from route registration.

### SCA Mode (Shared CA)

Both the client and PLC hold certificates signed by the same CA. The CA
certificate is configured on both sides. During the TLS handshake, each side
validates the other's certificate chain against the shared CA.

**No explicit route addition is required.** The CA-signed certificate is
sufficient authentication. Every connection sends a minimal `TlsConnectInfo`
(64 bytes, no `AddRemote` flag, no credentials).

```
Engineering PC                                PLC:8016
       |                                             |
       |---- TCP connect --------------------------->|
       |                                             |
       |<=== TLS 1.2 Handshake (mTLS) ==============>|
       |  Client cert -->  (signed by shared CA)     |
       |  <-- Server cert  (signed by shared CA)     |
       |  Both validate against shared CA            |
       |                                             |
       |  TlsConnectInfo Request (64 bytes)          |
       |  flags=None (0x00)                          |
       |  netId=client AmsNetId                      |
       |  hostname=client machine name               |
       |  user_len=0, pwd_len=0  (no credentials)    |
       |-------------------------------------------->|
       |                                             |
       |  TlsConnectInfo Response (64 bytes)         |
       |  flags=Response(0x01), error=NoError(0)     |
       |  netId=server AmsNetId                      |
       |<--------------------------------------------|
       |                                             |
       |<==== AMS frames (no AMS/TCP header) =======>|
```

### PSK Mode (Pre-Shared Key)

PSK mode uses TLS-PSK (RFC 4279) instead of certificates. Both the client and
PLC share a pre-configured identity and password. No certificates, keystores, or
CA infrastructure are required.

**Key derivation:** TwinCAT derives the 32-byte PSK from the identity and
password using `SHA-256(UPPER(identity) + password)`. The identity is
uppercased before concatenation (TwinCAT defaults to
`IdentityCaseSensitive="false"`).

**TLS details:** PSK mode uses TLS 1.2 with pure PSK cipher suites (AES-CBC
only). No TLS extensions are sent in the ClientHello. The connection uses
Bouncy Castle TLS (`bctls`) rather than the JDK's `SSLEngine`, since the JDK
provider does not support TLS-PSK.

**Route behavior:** The PSK identity entry in TwinCAT's `StaticRoutes.xml`
under `<Server><Tls><Psk>` acts as the route. A successful PSK TLS handshake
implicitly authorizes AMS communication — no separate route addition step or
credentials are needed.

```
Engineering PC                                PLC:8016
       |                                             |
       |---- TCP connect --------------------------->|
       |                                             |
       |<=== TLS 1.2 Handshake (TLS-PSK) ===========>|
       |  (pure PSK, no certificates)                |
       |                                             |
       |  TlsConnectInfo Request (64 bytes)          |
       |  flags=[] (empty)                           |
       |  netId=client AmsNetId                      |
       |  hostname=client machine name               |
       |  user_len=0, pwd_len=0  (no credentials)    |
       |-------------------------------------------->|
       |                                             |
       |  TlsConnectInfo Response (64 bytes)         |
       |  flags=Response(0x01), error=NoError(0)     |
       |  netId=server AmsNetId                      |
       |<--------------------------------------------|
       |                                             |
       |<==== AMS frames (no AMS/TCP header) =======>|
```

**TwinCAT configuration:** Add a PSK entry to `StaticRoutes.xml` on the PLC
under `<RemoteConnections>`:

```xml

<Server>
  <Tls>
    <Psk>
      <Identity>my-client</Identity>
      <Pwd>my-secret-password</Pwd>
    </Psk>
  </Tls>
</Server>
```

After saving, reinitialize the TwinCAT router (RUN → CONFIG → RUN) so the new
entry is loaded.

**Supported cipher suites:**

| Suite                             | Status      |
|-----------------------------------|-------------|
| `TLS_PSK_WITH_AES_256_CBC_SHA384` | ✓ Supported |
| `TLS_PSK_WITH_AES_128_CBC_SHA256` | ✓ Supported |
| `TLS_PSK_WITH_AES_256_CBC_SHA`    | ✓ Supported |
| `TLS_PSK_WITH_AES_128_CBC_SHA`    | ✓ Supported |

All GCM, CCM, ChaCha20, Camellia, and ARIA suites are rejected. Only pure PSK
suites are supported (no DHE_PSK, no ECDHE_PSK).

**Troubleshooting:**

- **Handshake failure:** Verify the identity and password match `StaticRoutes.xml`
  exactly. Remember that the identity is uppercased for key derivation.
- **ADS timeout after handshake:** `TlsConnectInfo` is required even in PSK mode.
  If the handshake succeeds but ADS commands time out, the `TlsConnectInfo`
  exchange may have failed.
- **Connection rate limiting:** TwinCAT may reject rapid sequential PSK
  connections. Add a delay between reconnection attempts.

---

## Repository Map

The code is a Kotlin/Gradle project using Netty for async networking.

```
build.gradle.kts                        # Kotlin 2.3.0, Netty 4.2
pki/
  generate.sh                           # Generate all PKI material (SCA + SSC)
  sca/                                  # Shared CA mode PKI material
    ca/rootCA.{pem,key}                 #   root CA
    client/client.{crt,key,p12}         #   client cert + PKCS#12 keystore
    plc/plc.{crt,key}                   #   PLC cert (for PLC-side config)
  ssc/
    client-keystore.p12                 # Self-signed mode keystore
src/main/kotlin/
  Config.kt                             # Target host/port, AMS IDs, PKI paths
  AddRoute.kt                           # Shared AddRoute connection logic
  AddRouteSelfSigned.kt                 # Route registration (SSC mode)
  SecureAdsSelfSigned.kt                # ADS client example (SSC mode)
  SecureAdsSharedCa.kt                  # ADS client example (SCA mode)
  SecureAdsPsk.kt                       # ADS client example (PSK mode)
  ads/
    TlsConnectInfo.kt                   # TlsConnectInfo structure + serde
    AmsHeader.kt                        # 32-byte AMS header + serde
    AmsFrame.kt                         # AMS header + data payload
    AmsNetId.kt                         # 6-byte AMS network ID
    AmsPort.kt                          # AMS port number
    AdsCommand.kt                       # ADS command enum (ReadState, etc.)
    AdsErrorCode.kt                     # ADS error codes
    AdsException.kt                     # Exception type
    AdsState.kt                         # ADS device state enum
    Shared.kt                           # Shared Netty resources (threads, timers)
    client/
      AdsClient.kt                      # Async ADS client (connect, readState, readDeviceInfo)
      AdsClientConfig.kt                # Client configuration
      SecureAds.kt                      # TLS context + TlsConnectInfo request builders
      SecureAdsConfig.kt                # SelfSignedConfig / SharedCaConfig / PskConfig
    commands/
      AdsReadDeviceInfo.kt              # ReadDeviceInfo request/response
      AdsReadState.kt                   # ReadState request/response
    netty/
      AmsFrameCodec.kt                  # Frame codec (with/without AMS/TCP header)
      TlsConnectInfoHandler.kt          # TlsConnectInfo exchange handler
      psk/
        BouncyCastlePskHandler.kt       # TLS-PSK transport handler (Bouncy Castle)
        PskException.kt                 # Typed PSK error classification
        PskHandshakeCompletionEvent.kt  # Transport-agnostic handshake event
```

### ADS Client Library

The `ads/` package is a minimal ADS implementation – just enough to demonstrate
Secure ADS connections. `AdsClient` supports `readDeviceInfo()` and
`readState()` commands over both standard ADS (port 48898, with AMS/TCP header)
and Secure ADS (port 8016, TLS + TlsConnectInfo, no AMS/TCP header). The
`AmsFrameCodec` handles both modes via an `includeTcpHeader` flag.

The `TlsConnectInfoHandler` sits between Netty's `SslHandler` and the
`AmsFrameCodec` in the pipeline. It sends the `TlsConnectInfo` request when the
TLS handshake completes, decodes the response, validates the error code, and
removes itself from the pipeline – leaving the connection ready for AMS frames.

### Examples

There are four runnable examples:

| Example               | Gradle Task              | Description                                                                                                |
|-----------------------|--------------------------|------------------------------------------------------------------------------------------------------------|
| `AddRouteSelfSigned`  | `runAddRouteSelfSigned`  | Route registration (SSC) — run once per PLC. Sends `TlsConnectInfo` with `AddRemote` flag and credentials. |
| `SecureAdsSelfSigned` | `runSecureAdsSelfSigned` | ADS client (SSC) — `ReadDeviceInfo` + `ReadState`. Requires prior route via `AddRouteSelfSigned`.          |
| `SecureAdsSharedCa`   | `runSecureAdsSharedCa`   | ADS client (SCA) — `ReadDeviceInfo` + `ReadState`. No prior route registration needed.                     |
| `SecureAdsPsk`        | `runSecureAdsPsk`        | ADS client (PSK) — `ReadDeviceInfo` + `ReadState`. No prior route registration needed.                     |

---

## Running the Examples

### Prerequisites

- JDK 17+
- TwinCAT 3 PLC/XAR running build 4024.0 or later

### Configuration

Edit `src/main/kotlin/Config.kt` to match your environment:

- `TARGET_HOST` -- PLC IP address
- `TARGET_PORT` -- Secure ADS port (default 8016)
- `SOURCE_AMS_NET_ID` -- your client's AMS Net ID
- `SOURCE_AMS_PORT` -- local AMS port for the client
- `TARGET_AMS_NET_ID` -- the PLC's AMS Net ID
- `TARGET_AMS_PORT` -- PLC runtime AMS port (typically 851)

### Generate PKI Material

Generate all certificates and keystores (SCA + SSC) in one step:

```bash
cd pki
./generate.sh <plc-ip> <client-ip>
```

### SCA Mode

1. Install the CA certificate and PLC certificate on the TwinCAT target per
   [Beckhoff documentation](https://infosys.beckhoff.com/content/1033/tc3_grundlagen/6798117643.html?id=2837414970195632676).
2. Connect (no route registration needed):
   ```bash
   ./gradlew runSecureAdsSharedCa
   ```

### SSC Mode

1. Set credentials for route registration:
   ```bash
   export ADS_USERNAME=Administrator
   export ADS_PASSWORD=1
   ```
2. Register a route (required for SSC, run once per PLC):
   ```bash
   ./gradlew runAddRouteSelfSigned
   ```
3. Communicate:
   ```bash
   ./gradlew runSecureAdsSelfSigned
   ```

### PSK Mode

1. Configure a PSK entry in `StaticRoutes.xml` on the PLC (see
   [PSK Mode](#psk-mode-pre-shared-key) above).
2. Set PSK credentials:
   ```bash
   export ADS_PSK_IDENTITY=my-client
   export ADS_PSK_PASSWORD=my-secret-password
   ```
3. Connect:
   ```bash
   ./gradlew runSecureAdsPsk
   ```

No certificates, keystores, or route registration steps are needed for PSK
mode.
