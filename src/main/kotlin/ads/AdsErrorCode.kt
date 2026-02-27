package ads

@Suppress("unused", "SpellCheckingInspection")
enum class AdsErrorCode(val code: UInt) {

  // region Global error codes

  /** No error. */
  ERR_NOERROR(0x0000u),

  /** Internal error. */
  ERR_INTERNAL(0x0001u),

  /** No real time. */
  ERR_NORTIME(0x0002u),

  /** Allocation locked memory error. */
  ERR_ALLOCLOCKEDMEM(0x0003u),

  /**
   * Mailbox full - the ADS message could not be sent. Reducing the number of ADS messages per cycle
   * will help.
   */
  ERR_INSERTMAILBOX(0x0004u),

  /** Wrong HMSG. */
  ERR_WRONGRECEIVEHMSG(0x0005u),

  /** Target port not found - ADS server is not started, not reachable or not installed. */
  ERR_TARGETPORTNOTFOUND(0x0006u),

  /** Target computer not found - AMS route was not found. */
  ERR_TARGETMACHINENOTFOUND(0x0007u),

  /** Unknown command ID. */
  ERR_UNKNOWNCMDID(0x0008u),

  /** Invalid task ID. */
  ERR_BADTASKID(0x0009u),

  /** No IO. */
  ERR_NOIO(0x000Au),

  /** Unknown AMS command. */
  ERR_UNKNOWNAMSCMD(0x000Bu),

  /** Win32 error. */
  ERR_WIN32ERROR(0x000Cu),

  /** Port not connected. */
  ERR_PORTNOTCONNECTED(0x000Du),

  /** Invalid AMS length. */
  ERR_INVALIDAMSLENGTH(0x000Eu),

  /** Invalid AMS Net ID. */
  ERR_INVALIDAMSNETID(0x000Fu),

  /** Installation level is too low - TwinCAT 2 license error. */
  ERR_LOWINSTLEVEL(0x0010u),

  /** No debugging available. */
  ERR_NODEBUGINTAVAILABLE(0x0011u),

  /** Port disabled - TwinCAT system service not started. */
  ERR_PORTDISABLED(0x0012u),

  /** Port already connected. */
  ERR_PORTALREADYCONNECTED(0x0013u),

  /** AMS Sync Win32 error. */
  ERR_AMSSYNC_W32ERROR(0x0014u),

  /** AMS Sync Timeout. */
  ERR_AMSSYNC_TIMEOUT(0x0015u),

  /** AMS Sync error. */
  ERR_AMSSYNC_AMSERROR(0x0016u),

  /** No index map for AMS Sync available. */
  ERR_AMSSYNC_NOINDEXINMAP(0x0017u),

  /** Invalid AMS port. */
  ERR_INVALIDAMSPORT(0x0018u),

  /** No memory. */
  ERR_NOMEMORY(0x0019u),

  /** TCP send error. */
  ERR_TCPSEND(0x001Au),

  /** Host unreachable. */
  ERR_HOSTUNREACHABLE(0x001Bu),

  /** Invalid AMS fragment. */
  ERR_INVALIDAMSFRAGMENT(0x001Cu),

  /** TLS send error secure ADS connection failed. */
  ERR_TLSSEND(0x001Du),

  /** Access denied secure ADS access denied. */
  ERR_ACCESSDENIED(0x001Eu),

  // endregion

  // region Router error codes

  /** Locked memory cannot be allocated. */
  ROUTERERR_NOLOCKEDMEMORY(0x0500u),

  /** The router memory size could not be changed. */
  ROUTERERR_RESIZEMEMORY(0x0501u),

  /** The mailbox has reached the maximum number of possible messages. */
  ROUTERERR_MAILBOXFULL(0x0502u),

  /** The Debug mailbox has reached the maximum number of possible messages. */
  ROUTERERR_DEBUGBOXFULL(0x0503u),

  /** The port type is unknown. */
  ROUTERERR_UNKNOWNPORTTYPE(0x0504u),

  /** The router is not initialized. */
  ROUTERERR_NOTINITIALIZED(0x0505u),

  /** The port number is already assigned. */
  ROUTERERR_PORTALREADYINUSE(0x0506u),

  /** The port is not registered. */
  ROUTERERR_NOTREGISTERED(0x0507u),

  /** The maximum number of ports has been reached. */
  ROUTERERR_NOMOREQUEUES(0x0508u),

  /** The port is invalid. */
  ROUTERERR_INVALIDPORT(0x0509u),

  /** The router is not active. */
  ROUTERERR_NOTACTIVATED(0x050Au),

  /** The mailbox has reached the maximum number for fragmented messages. */
  ROUTERERR_FRAGMENTBOXFULL(0x050Bu),

  /** A fragment timeout has occurred. */
  ROUTERERR_FRAGMENTTIMEOUT(0x050Cu),

  /** The port is removed. */
  ROUTERERR_TOBEREMOVED(0x050Du),

  // endregion

  // region General ADS error codes

  /** General device error. */
  ADSERR_DEVICE_ERROR(0x0700u),

  /** Service is not supported by the server. */
  ADSERR_DEVICE_SRVNOTSUPP(0x0701u),

  /** Invalid index group. */
  ADSERR_DEVICE_INVALIDGRP(0x0702u),

  /** Invalid index offset */
  ADSERR_DEVICE_INVALIDOFFSET(0x0703u),

  /**
   * Reading or writing not permitted. Several causes are possible. For example, an incorrect
   * password was entered when creating routes.
   */
  ADSERR_DEVICE_INVALIDACCESS(0x0704u),

  /** Parameter size not correct. */
  ADSERR_DEVICE_INVALIDSIZE(0x0705u),

  /** Invalid data values. */
  ADSERR_DEVICE_INVALIDDATA(0x0706u),

  /** Device is not ready to operate. */
  ADSERR_DEVICE_NOTREADY(0x0707u),

  /** Device is busy. */
  ADSERR_DEVICE_BUSY(0x0708u),

  /**
   * Invalid operating system context. This can result from use of ADS blocks in different tasks. It
   * may be possible to resolve this through multitasking synchronization in the PLC.
   */
  ADSERR_DEVICE_INVALIDCONTEXT(0x0709u),

  /** Insufficient memory. */
  ADSERR_DEVICE_NOMEMORY(0x070Au),

  /** Invalid parameter values. */
  ADSERR_DEVICE_INVALIDPARM(0x070Bu),

  /** Not found (files,...). */
  ADSERR_DEVICE_NOTFOUND(0x070Cu),

  /** Syntax error in file or command. */
  ADSERR_DEVICE_SYNTAX(0x070Du),

  /** Objects do not match. */
  ADSERR_DEVICE_INCOMPATIBLE(0x070Eu),

  /** Object already exists. */
  ADSERR_DEVICE_EXISTS(0x070Fu),

  /** Symbol not found. */
  ADSERR_DEVICE_SYMBOLNOTFOUND(0x0710u),

  /** Invalid symbol version. This can occur due to an online change. Create a new handle. */
  ADSERR_DEVICE_SYMBOLVERSIONINVALID(0x0711u),

  /** Device (server) is in invalid state. */
  ADSERR_DEVICE_INVALIDSTATE(0x0712u),

  /** Ads TransMode not supported. */
  ADSERR_DEVICE_TRANSMODENOTSUPP(0x0713u),

  /** Notification handle is invalid. */
  ADSERR_DEVICE_NOTIFYHNDINVALID(0x0714u),

  /** Notification client not registered. */
  ADSERR_DEVICE_CLIENTUNKNOWN(0x0715u),

  /** No further handle available. */
  ADSERR_DEVICE_NOMOREHDLS(0x0716u),

  /** Notification size too large. */
  ADSERR_DEVICE_INVALIDWATCHSIZE(0x0717u),

  /** Device not initialized. */
  ADSERR_DEVICE_NOTINIT(0x0718u),

  /** Device has a timeout. */
  ADSERR_DEVICE_TIMEOUT(0x0719u),

  /** Interface query failed. */
  ADSERR_DEVICE_NOINTERFACE(0x071Au),

  /** Wrong interface requested. */
  ADSERR_DEVICE_INVALIDINTERFACE(0x071Bu),

  /** Class ID is invalid. */
  ADSERR_DEVICE_INVALIDCLSID(0x071Cu),

  /** Object ID is invalid. */
  ADSERR_DEVICE_INVALIDOBJID(0x071Du),

  /** Request pending. */
  ADSERR_DEVICE_PENDING(0x071Eu),

  /** Request is aborted. */
  ADSERR_DEVICE_ABORTED(0x071Fu),

  /** Signal warning. */
  ADSERR_DEVICE_WARNING(0x0720u),

  /** Invalid array index. */
  ADSERR_DEVICE_INVALIDARRAYIDX(0x0721u),

  /** Symbol not active. */
  ADSERR_DEVICE_SYMBOLNOTACTIVE(0x0722u),

  /**
   * Access denied. Several causes are possible. For example, a unidirectional ADS route is used in
   * the opposite direction.
   */
  ADSERR_DEVICE_ACCESSDENIED(0x0723u),

  /** Missing license. */
  ADSERR_DEVICE_LICENSENOTFOUND(0x0724u),

  /** License expired. */
  ADSERR_DEVICE_LICENSEEXPIRED(0x0725u),

  /** License exceeded. */
  ADSERR_DEVICE_LICENSEEXCEEDED(0x0726u),

  /** Invalid license. */
  ADSERR_DEVICE_LICENSEINVALID(0x0727u),

  /** License problem: System ID is invalid. */
  ADSERR_DEVICE_LICENSESYSTEMID(0x0728u),

  /** License not limited in time. */
  ADSERR_DEVICE_LICENSENOTIMELIMIT(0x0729u),

  /** Licensing problem: time in the future. */
  ADSERR_DEVICE_LICENSEFUTUREISSUE(0x072Au),

  /** License period too long. */
  ADSERR_DEVICE_LICENSETIMETOLONG(0x072Bu),

  /** Exception at system startup. */
  ADSERR_DEVICE_EXCEPTION(0x072Cu),

  /** License file read twice. */
  ADSERR_DEVICE_LICENSEDUPLICATED(0x072Du),

  /** Invalid signature. */
  ADSERR_DEVICE_SIGNATUREINVALID(0x072Eu),

  /** Invalid certificate. */
  ADSERR_DEVICE_CERTIFICATEINVALID(0x072Fu),

  /** Public key not known from OEM. */
  ADSERR_DEVICE_LICENSEOEMNOTFOUND(0x0730u),

  /** License not valid for this system ID. */
  ADSERR_DEVICE_LICENSERESTRICTED(0x0731u),

  /** Demo license prohibited. */
  ADSERR_DEVICE_LICENSEDEMODENIED(0x0732u),

  /** Invalid function ID. */
  ADSERR_DEVICE_INVALIDFNCID(0x0733u),

  /** Outside the valid range. */
  ADSERR_DEVICE_OUTOFRANGE(0x0734u),

  /** Invalid alignment. */
  ADSERR_DEVICE_INVALIDALIGNMENT(0x0735u),

  /** Invalid platform level. */
  ADSERR_DEVICE_LICENSEPLATFORM(0x0736u),

  /** Context-forward to passive level. */
  ADSERR_DEVICE_FORWARD_PL(0x0737u),

  /** Context forward to dispatch level. */
  ADSERR_DEVICE_FORWARD_DL(0x0738u),

  /** Context-forward to real-time. */
  ADSERR_DEVICE_FORWARD_RT(0x0739u),

  /** Client error. */
  ADSERR_CLIENT_ERROR(0x0740u),

  /** Service contains an invalid parameter. */
  ADSERR_CLIENT_INVALIDPARM(0x0741u),

  /** Polling list is empty. */
  ADSERR_CLIENT_LISTEMPTY(0x0742u),

  /** Var connection already in use. */
  ADSERR_CLIENT_VARUSED(0x0743u),

  /** The called ID is already in use. */
  ADSERR_CLIENT_DUPLINVOKEID(0x0744u),

  /**
   * Timeout has occurred the remote terminal is not responding in the specified ADS timeout. The
   * route setting of the remote terminal may be configured incorrectly.
   */
  ADSERR_CLIENT_SYNCTIMEOUT(0x0745u),

  /** Error in Win32 subsystem. */
  ADSERR_CLIENT_W32ERROR(0x0746u),

  /** Invalid client timeout value. */
  ADSERR_CLIENT_TIMEOUTINVALID(0x0747u),

  /** Port not open. */
  ADSERR_CLIENT_PORTNOTOPEN(0x0748u),

  /** No AMS address. */
  ADSERR_CLIENT_NOAMSADDR(0x0749u),

  /** Internal error in Ads sync. */
  ADSERR_CLIENT_SYNCINTERNAL(0x0750u),

  /** Hash table overflow. */
  ADSERR_CLIENT_ADDHASH(0x0751u),

  /** Key not found in the table. */
  ADSERR_CLIENT_REMOVEHASH(0x0752u),

  /** No symbols in the cache. */
  ADSERR_CLIENT_NOMORESYM(0x0753u),

  /** Invalid response received. */
  ADSERR_CLIENT_SYNCRESINVALID(0x0754u),

  /** Sync Port is locked. */
  ADSERR_CLIENT_SYNCPORTLOCKED(0x0755u),

  /** The request was canceled. */
  ADSERR_CLIENT_REQUESTCANCELLED(0x0756u),

  // endregion

  // region RTime error codes

  /** Internal error in the real-time system. */
  RTERR_INTERNAL(0x1000u),

  /** Timer value is not valid. */
  RTERR_BADTIMERPERIODS(0x1001u),

  /** Task pointer has the invalid value 0 (zero). */
  RTERR_INVALIDTASKPTR(0x1002u),

  /** Stack pointer has the invalid value 0 (zero). */
  RTERR_INVALIDSTACKPTR(0x1003u),

  /** The request task priority is already assigned. */
  RTERR_PRIOEXISTS(0x1004u),

  /** No free TCB (Task Control Block) available. The maximum number of TCBs is 64. */
  RTERR_NOMORETCB(0x1005u),

  /** No free semaphores available. The maximum number of semaphores is 64. */
  RTERR_NOMORESEMAS(0x1006u),

  /** No free space available in the queue. The maximum number of positions in the queue is 64. */
  RTERR_NOMOREQUEUES(0x1007u),

  /** An external synchronization interrupt is already applied. */
  RTERR_EXTIRQALREADYDEF(0x100Du),

  /** No external sync interrupt applied. */
  RTERR_EXTIRQNOTDEF(0x100Eu),

  /** Application of the external synchronization interrupt has failed. */
  RTERR_EXTIRQINSTALLFAILED(0x100Fu),

  /** Call of a service function in the wrong context */
  RTERR_IRQLNOTLESSOREQUAL(0x1010u),

  /** Intel VT-x extension is not supported. */
  RTERR_VMXNOT_SUPPORTED(0x1017u),

  /** Intel VT-x extension is not enabled in the BIOS. */
  RTERR_VMXDISABLED(0x1018u),

  /** Missing function in Intel VT-x extension. */
  RTERR_VMXCONTROLSMISSING(0x1019u),

  /** Activation of Intel VT-x fails. */
  RTERR_VMXENABLEFAILS(0x101Au);

  // endregion

  fun isOk(): Boolean = this == ERR_NOERROR

  companion object {
    private val codes = entries.associateBy(AdsErrorCode::code)

    /** Look up an [AdsErrorCode] by its [code]. */
    fun from(code: UInt) = codes[code] ?: ERR_INTERNAL
  }
}
