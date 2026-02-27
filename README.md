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
single request/response exchange that serves **dual purpose** depending on the
flags:

- **Route addition** (first connection to a new peer): the `AddRemote` flag
  is set. Credentials may be included (SSC mode) or omitted (SCA mode, where the
  CA-signed certificate is sufficient authentication). On success, the PLC
  persists the route.
- **Established-route communication** (subsequent connections): no `AddRemote`
  flag. Authentication is via mTLS alone (SCA mode) or mTLS + certificate
  fingerprint pinning (SSC mode). Credentials are never sent.

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
- **PSK** – Pre-Shared Key (operates entirely at the TLS layer; not covered here)

### SCA Mode (Shared CA)

Both the client and PLC hold certificates signed by the same CA. The CA
certificate is configured on both sides. During the TLS handshake, each side
validates the other's certificate chain against the shared CA.

**Route addition:** The client sends a `TlsConnectInfo` with the `AddRemote`
flag set and no credentials. The CA-signed certificate is the sole
authentication mechanism. No username or password is exchanged.
The `IpAddr` and `IgnoreCn` flags are environment-dependent (see note above);
the examples here use `AddRemote | IpAddr | IgnoreCn` (0xE0).

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
       |  flags=AddRemote [|IpAddr] [|IgnoreCn]      |
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

**Established route:** The client sends flags `None` (0x00), no credentials,
exactly 64 bytes. The certificate chain validated during the TLS handshake is
sufficient.

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

---

## Repository Map

The code is a Kotlin/Gradle project using Netty for async networking.

```
build.gradle.kts                        # Kotlin 2.3.0, Netty 4.2, 4 run tasks
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
  AddRouteSharedCa.kt                   # Route registration (SCA mode)
  SecureAdsSelfSigned.kt                # ADS client example (SSC mode)
  SecureAdsSharedCa.kt                  # ADS client example (SCA mode)
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
      SecureAdsConfig.kt                # SelfSignedConfig / SharedCaConfig
    commands/
      AdsReadDeviceInfo.kt              # ReadDeviceInfo request/response
      AdsReadState.kt                   # ReadState request/response
    netty/
      AmsFrameCodec.kt                 # Frame codec (with/without AMS/TCP header)
      TlsConnectInfoHandler.kt         # TlsConnectInfo exchange handler
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

There are four runnable examples, organized into two pairs:

**Route registration** (run once to establish a route on the PLC):

- `AddRouteSelfSigned` -- uses a self-signed cert from the `pki/ssc/` directory,
  sends `TlsConnectInfo` with `AddRemote` flag and credentials
- `AddRouteSharedCa` -- uses a CA-signed cert from the `pki/sca/` directory,
  sends `TlsConnectInfo` with `AddRemote` flag, no credentials

**ADS communication** (requires an established route):

- `SecureAdsSelfSigned` -- connects with the self-signed cert, performs
  `ReadDeviceInfo` and `ReadState`
- `SecureAdsSharedCa` -- connects with the CA-signed cert, performs
  `ReadDeviceInfo` and `ReadState`

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
2. Register a route, then communicate:
   ```bash
   ./gradlew runAddRouteSharedCa
   ./gradlew runSecureAdsSharedCa
   ```

### SSC Mode

1. Set credentials for route registration:
   ```bash
   export ADS_USERNAME=Administrator
   export ADS_PASSWORD=1
   ```
2. Register a route, then communicate:
   ```bash
   ./gradlew runAddRouteSelfSigned
   ./gradlew runSecureAdsSelfSigned
   ```
