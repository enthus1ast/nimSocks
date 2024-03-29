#
#
#                  nimSocks
#          SOCKS4/4a/5 proxy server
#            (c) Copyright 2020
#        David Krause, Tobias Freitag
#
#    See the file "LICENSE", included in this
#    distribution, for details about the copyright.
## SOCKS4/4a/5 type definitions
# {.push raises: [Defect].}
import net, asyncnet, asyncdispatch, strutils
import dbg, strformat, std/enumutils

type
  RESERVED =  distinct byte

const
  DEFAULT_PORT* = 1080
  RESERVED_VALUE: RESERVED = 0x00.RESERVED
  IP_V4_ADDRESS_LEN = 4
  IP_V6_ADDRESS_LEN = 16
  NULL* = 0x00.byte

type
  SOCKS_VERSION* {.pure.} = enum
    SOCKS_V4 = 0x04.byte # same as 4a
    SOCKS_V5 = 0x05.byte
  RequestMessageSelection* = ref object
    version*: SOCKS_VERSION
    methodsLen*: byte
    methods*: seq[AuthenticationMethod]
  ResponseMessageSelection* = ref object
    version*: SOCKS_VERSION
    selectedMethod*: AuthenticationMethod
  AuthenticationMethod* {.pure.} = enum
    NO_AUTHENTICATION_REQUIRED = 0x00.byte
    GSSAPI = 0x01.byte
    USERNAME_PASSWORD = 0x02.byte
    # to X'7F' IANA ASSIGNED = 0x03
    # to X'FE' RESERVED FOR PRIVATE METHODS = 0x80
    # RESERVED = 0x03.byte .. 0xFE.byte ## <-- would be nice to have
    NO_ACCEPTABLE_METHODS = 0xFF.byte
  AuthVersion* {.pure.} = enum
    AuthVersionV1 = 0x01.byte
  UserPasswordStatus* {.pure.} = enum
    SUCCEEDED = 0x00
    FAILED = 0x01
  SocksCmd* {.pure.} = enum
    CONNECT = 0x01.byte
    BIND = 0x02.byte
    UDP_ASSOCIATE = 0x03.byte
  ATYP* {.pure.} = enum
    IP_V4_ADDRESS = 0x01.byte
    DOMAINNAME = 0x03.byte
    IP_V6_ADDRESS = 0x04.byte
  REP* {.pure.} = enum
   SUCCEEDED = 0x00.byte
   GENERAL_SOCKS_SERVER_FAILURE = 0x01.byte
   CONNECTION_NOT_ALLOWED_BY_RULESET = 0x02.byte
   NETWORK_UNREACHABLE = 0x03.byte
   HOST_UNREACHABLE = 0x04.byte
   CONNECTION_REFUSED = 0x05.byte
   TTL_EXPIRED = 0x06.byte
   COMMAND_NOT_SUPPORTED = 0x07.byte
   ADDRESS_TYPE_NOT_SUPPORTED = 0x08.byte
   # to X'FF' unassigned = 0x09.byte
  SocksVersionRef* = ref object
    socksVersion*: SOCKS_VERSION

  # Socks5
  SocksRequest* = ref object
    version*: SOCKS_VERSION
    cmd*: SocksCmd
    rsv*: RESERVED
    atyp*: ATYP
    dst_addr*: seq[byte]
    dst_port*: tuple[h: byte, l: byte]
  SocksResponse* = ref object
    version*: SOCKS_VERSION
    rep*: REP
    rsv*: RESERVED
    atyp*: ATYP
    bnd_addr*: seq[byte]
    bnd_port*: tuple[h: byte, l: byte]
  SocksUserPasswordRequest* = ref object
    authVersion*: AuthVersion
    ulen*: byte
    uname*: seq[byte]
    plen*: byte
    passwd*: seq[byte]
  SocksUserPasswordResponse* = ref object
   authVersion*: AuthVersion
   status*: UserPasswordStatus

  ## Socks4 & Socks4a
  REP4* {.pure.} = enum
    REQUEST_GRANTED = 0x5A.byte
    REQUEST_REJECTED_OR_FAILED = 0x05B.byte
  Socks4Cmd* {.pure.} = enum
    CONNECT = 0x01.byte
    BIND = 0x02.byte
  Socks4Request* = ref object
    socksVersion*: SOCKS_VERSION
    cmd*: Socks4Cmd
    dst_port*: tuple[h: byte, l: byte]
    dst_ip*: seq[byte] # 4 byte array! # TODO
    userid*: seq[byte] # null terminated but not captured!
  Socks4Response* = ref object
    socks4ReplyVersion*: byte
    rep*: REP4
    dst_port*: tuple[h: byte, l: byte]
    dst_ip*: seq[byte] # 4 byte array! # TODO

proc toEnum*[T](val: byte): T {.raises: ValueError.} =
  for tval in T:
    if tval.byte == val: return T(val)
  raise newException(ValueError, fmt"'{val}' is not a valid enum of '{$T}'")

proc toBytes*(str: string): seq[byte] =
  result = @[]
  for ch in str:
    result.add ch.byte

proc toBytes*[T](arr: openarray[T]): seq[byte] =
  ## for converting ip
  result = @[]
  for el in arr:
    result.add el.byte

proc toString*[T](arr: openarray[T]): string=
  ## for converting ip
  for el in arr:
    result.add el.char

proc `$`*(obj: seq[byte]): string = ## TODO usage of this should be cstring, for username password etc
  result = ""
  for ch in obj:
    result.add ch.char

proc contains*[T](xx: set[T]; yy: seq[T]): bool =
  for elem in yy:
    if elem in xx: return true
  return false

proc `in`*(bytesMethod: seq[byte], authMethods: set[AuthenticationMethod]): bool =
  for byteMethod in bytesMethod:
    if byteMethod.AuthenticationMethod in authMethods: return true
  return false

proc `$`*(obj: ResponseMessageSelection): string =
  result = ""
  result.add obj.version.char
  result.add obj.selectedMethod.char

proc `$`*(obj: SocksResponse): string =
  result = ""
  result.add obj.version.char
  result.add obj.rep.char
  result.add obj.rsv.char
  result.add obj.atyp.char
  result.add obj.bnd_addr.toString()
  result.add obj.bnd_port.h.char
  result.add obj.bnd_port.l.char

proc `$`*(obj: SocksRequest): string =
  result = ""
  result.add obj.version.char
  result.add obj.cmd.char
  result.add obj.rsv.char
  result.add obj.atyp.char
  result.add obj.dst_addr.toString()
  result.add obj.dst_port.h.char
  result.add obj.dst_port.l.char

proc `$`*(obj: SocksUserPasswordResponse): string =
  result = ""
  result.add obj.authVersion.char
  result.add obj.status.char

proc `$`*(obj: RequestMessageSelection): string =
  result = ""
  result.add obj.version.char
  result.add obj.methodsLen.char
  result.add obj.methods.toString()

proc `$`*(obj: SocksUserPasswordRequest): string =
  result = ""
  result.add obj.authVersion.char
  result.add obj.ulen.char
  result.add obj.uname.toString()
  result.add obj.plen.char
  result.add obj.passwd.toString()

proc `$`*(obj: Socks4Request): string =
  result = ""
  result.add obj.socksVersion.char
  result.add obj.cmd.char
  result.add obj.dst_port.h.char
  result.add obj.dst_port.l.char
  result.add obj.dst_ip.toString()
  result.add obj.userid.toString()
  result.add NULL.char

proc `$`*(obj: Socks4Response): string =
  result = ""
  result.add obj.socks4ReplyVersion.char
  result.add obj.rep.char
  result.add obj.dst_port.h.char
  result.add obj.dst_port.l.char
  result.add obj.dst_ip.toString()

proc toSeq*(str: string): seq[byte] =
  result = @[]
  for ch in str:
    result.add ch.byte

proc toSeq*[T](obj: seq[byte], myType : typedesc[T] ): seq[T] =
  result = @[]
  for ch in obj:
    result.add ch.T

proc toSeq*[T](obj: set[byte]): seq[T] =
  result = @[]
  for ch in obj:
    result.add ch.T

proc toSeq*[T](obj: set[T]): seq[T] =
  result = @[]
  for ch in obj:
    result.add ch.T

proc port*(t: tuple[h, l: byte]): Port =
  return Port(t.h.int * 256 + t.l.int)

proc unPort*(p: Port): tuple[h, l: byte] =
  return ((p.int div 256).byte, (p.int mod 256).byte)

proc parseHost(host: string): tuple[atyp: ATYP, data: seq[byte]] =
  var ipaddr: IpAddress
  try:
    ipaddr = host.parseIpAddress()
    case ipaddr.family
    of IPv4:
      result.atyp = IP_V4_ADDRESS
      result.data = ipaddr.address_v4.toBytes()
    of IPv6:
      result.atyp = IP_V6_ADDRESS
      result.data = ipaddr.address_v6.toBytes()
  except:
      result.atyp = DOMAINNAME
      result.data = host.len.byte & host.toBytes()

proc newSocksRequest*(
    cmd: SocksCmd, address: string, port: Port,
    socksVersion: SOCKS_VERSION = SOCKS_V5
): SocksRequest =
  if address.len == 0: raise newException(ValueError, "address should not be empty")
  result = SocksRequest()
  result.version  = socksVersion
  result.cmd = cmd
  result.rsv = RESERVED_VALUE
  (result.atyp, result.dst_addr) = address.parseHost()
  result.dst_port = port.unPort()

proc newSocksResponse*(socksRequest: SocksRequest, rep: REP): SocksResponse =
  result = SocksResponse()
  result.version = socksRequest.version
  result.rep = rep
  result.rsv = RESERVED_VALUE
  result.atyp = socksRequest.atyp
  case result.atyp.ATYP
  of IP_V4_ADDRESS, IP_V6_ADDRESS:
    result.bnd_addr = socksRequest.dst_addr
  of DOMAINNAME:
    result.bnd_addr = socksRequest.dst_addr.len.byte & socksRequest.dst_addr
  result.bnd_port = socksRequest.dst_port

proc newRequestMessageSelection*(version: SOCKS_VERSION, methods: set[AuthenticationMethod]): RequestMessageSelection =
  result = RequestMessageSelection()
  result.version = version
  result.methodsLen = methods.toSeq().len.byte
  result.methods = methods.toSeq()

proc newResponseMessageSelection*(version: SOCKS_VERSION, selectedMethod: AuthenticationMethod): ResponseMessageSelection =
  result = ResponseMessageSelection()
  result.version = version
  result.selectedMethod = selectedMethod

proc newSocksUserPasswordRequest*(username: string, password: string): SocksUserPasswordRequest =
  result = SocksUserPasswordRequest()
  result.authVersion = AuthVersionV1
  result.ulen = username.len.byte
  result.uname = username.toBytes()
  result.plen =  password.len.byte
  result.passwd =  password.toBytes()

proc parseDestAddress*(bytes: seq[byte], atyp: ATYP): string =
  # TODO should use proper type!
  result = ""
  for idx, ch in bytes:
    case atyp
    of DOMAINNAME:
      result.add(ch.chr())
    of IP_V4_ADDRESS:
      result.add($ch)
      if idx != IP_V4_ADDRESS_LEN-1: result.add('.')
    of IP_V6_ADDRESS:
      # TODO
      result.add((ch).toHex())
      if idx != IP_V6_ADDRESS_LEN-1 and idx mod 2 == 1: result.add(':')

proc recvByte*(client: AsyncSocket | Socket): Future[byte] {.multisync.} =
  # return (await client.recv(1))[0].byte # crash 18.1
  var dat = await client.recv(1) # TODO remove workaround someday
  return dat[0].byte

proc recvBytes*(client: AsyncSocket | Socket, count: int): Future[seq[byte]] {.multisync.} =
  return (await client.recv(count)).toSeq()

proc recvNullTerminated*(client: AsyncSocket): Future[seq[byte]] {.async.} =
  ## TODO should we limit the reading to a fixed value?
  result = @[]
  var ch: byte
  while true:
    let buf = (await client.recv(1))
    if buf.len == 0: raise newException(ValueError, "recvNullTerminated has read to the end! (this should not happen in SOCKS)")
    ch = buf[0].byte
    if ch == NULL: break
    result.add ch

proc recvSocksUserPasswordRequest*(client:AsyncSocket, obj: SocksUserPasswordRequest): Future[bool] {.async.} =
  try:
    obj.authVersion = (await client.recvByte).AuthVersion
    if obj.authVersion != AuthVersionV1: return false

    obj.ulen = await client.recvByte
    if obj.ulen == 0x00: return false

    obj.uname = await client.recvBytes(obj.ulen.int)
    if obj.uname.len == 0: return false

    obj.plen = await client.recvByte
    if obj.plen == 0x00: return false

    obj.passwd = await client.recvBytes(obj.plen.int)
    if obj.passwd.len == 0: return false
  except:
    return false
  return true

proc parseEnum[T](bt: byte): T =
  try:
    return T(bt)
  except:
    raise newException(ValueError, "invalid byte")

proc inEnum[T](bt: byte): bool =
  try:
    discard parseEnum[T](bt)
    return true
  except:
    return false

proc recvSocksRequest*(client:AsyncSocket, obj: SocksRequest): Future[bool] {.async.} =
  try:
    obj.version = toEnum[SOCKS_VERSION](await client.recvByte)
    obj.cmd = toEnum[SocksCmd](await client.recvByte)

    obj.rsv = (await client.recvByte).RESERVED
    if obj.rsv.byte != RESERVED_VALUE.byte: return false

    obj.atyp = toEnum[ATYP](await client.recvByte)
  except:
    dbg getCurrentExceptionMsg()
    return false

  ## TODO these still fail hard
  obj.dst_addr = case obj.atyp.ATYP
    of IP_V4_ADDRESS: await client.recvBytes(IP_V4_ADDRESS_LEN)
    of DOMAINNAME: await client.recvBytes((await client.recvByte).int)
    of IP_V6_ADDRESS: await client.recvBytes(IP_V6_ADDRESS_LEN)
  obj.dst_port = (await client.recvByte, await client.recvByte)
  return true

proc recvSocksResponse*(client:AsyncSocket | Socket, obj: SocksResponse): Future[bool] {.multisync.} =
  try:
    obj.version = toEnum[SOCKS_VERSION](await client.recvByte)
    obj.rep = toEnum[REP](await client.recvByte)
    obj.rsv = (await client.recvByte).RESERVED
    if obj.rsv.byte != RESERVED_VALUE.byte: return false

    obj.atyp = toEnum[ATYP](await client.recvByte)
    obj.bnd_addr = case obj.atyp.ATYP
      of IP_V4_ADDRESS: await client.recvBytes(IP_V4_ADDRESS_LEN)
      of DOMAINNAME: await client.recvBytes((await client.recvByte).int)
      of IP_V6_ADDRESS: await client.recvBytes(IP_V6_ADDRESS_LEN)

    obj.bnd_port = (await client.recvByte, await client.recvByte)
  except:
    return false
  return true


proc recvRequestMessageSelection*(client:AsyncSocket, obj: RequestMessageSelection): Future[bool] {.async.} =
  obj.version = SOCKS_V5

  try:
    obj.methodsLen = await client.recvByte
  except:
    return false
  if obj.methodsLen < 1: return false

  try:
    obj.methods = (await client.recvBytes(obj.methodsLen.int)).toSeq(AuthenticationMethod)
  except:
    return false

  return true


proc recvResponseMessageSelection*(client:AsyncSocket | Socket, obj: ResponseMessageSelection): Future[bool] {.multisync.} =
  try:
    obj.version = toEnum[SOCKS_VERSION](await client.recvByte)
  except:
    return false

  try:
    obj.selectedMethod = toEnum[AuthenticationMethod](await client.recvByte)
  except:
    return false

  return true


proc recvSocksUserPasswordResponse*(client:AsyncSocket | Socket, obj: SocksUserPasswordResponse): Future[bool] {.multisync.} =
  try:
    obj.authVersion = toEnum[AuthVersion](await client.recvByte)
    if obj.authVersion != AuthVersionV1: return false
    obj.status = toEnum[UserPasswordStatus](await client.recvByte)
  except:
    dbg "recvSocksUserPasswordResponse failed"
    return false
  return true

proc recvSocksVersion*(client:AsyncSocket, socksVersionRef: SocksVersionRef): Future[bool] {.async.} =
  try:
    socksVersionRef.socksVersion = toEnum[SOCKS_VERSION](await client.recvByte)
  except:
    dbg "recvSocksVersion failed"
    return false
  return true

proc recvSocks4Request*(client:AsyncSocket, obj: Socks4Request): Future[bool] {.async.} =
  obj.socksVersion = SOCKS_V4
  try:
    obj.cmd = toEnum[Socks4Cmd](await client.recvByte)
    obj.dst_port = (await client.recvByte, await client.recvByte)
    obj.dst_ip = await client.recvBytes(IP_V4_ADDRESS_LEN)
    obj.userid = await client.recvNullTerminated()
  except:
    dbg getCurrentExceptionMsg()
    return false
  return true

proc newSocks4Response*(rep: REP4): Socks4Response =
  result = Socks4Response()
  result.socks4ReplyVersion = NULL
  result.rep = rep
  result.dst_ip = @[0.byte,0.byte,0.byte,0.byte] # ignored
  result.dst_port = (0.byte,0.byte) # ignored

proc isSocks4aHack*(dst_ip: seq[byte]): bool =
  return
    dst_ip[0] == NULL and
    dst_ip[1] == NULL and
    dst_ip[2] == NULL and
    dst_ip[3] != NULL