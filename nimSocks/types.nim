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

import net, asyncnet, asyncdispatch, strutils
import dbg

const
  DEFAULT_PORT* = 1080
  RESERVED = 0x00.byte
  IP_V4_ADDRESS_LEN = 4
  IP_V6_ADDRESS_LEN = 16
  NULL* = 0x00.byte

type
  SOCKS_VERSION* = enum
    SOCKS_V4 = 0x04.byte # same as 4a
    SOCKS_V5 = 0x05.byte
  RequestMessageSelection* = ref object
    version*: SOCKS_VERSION
    methodsLen*: byte
    methods*: seq[AuthenticationMethod]
  ResponseMessageSelection* = ref object
    version*: SOCKS_VERSION
    selectedMethod*: AuthenticationMethod
  AuthenticationMethod* = enum
    NO_AUTHENTICATION_REQUIRED = 0x00.byte
    GSSAPI = 0x01.byte
    USERNAME_PASSWORD = 0x02.byte
    # to X'7F' IANA ASSIGNED = 0x03
    # to X'FE' RESERVED FOR PRIVATE METHODS = 0x80
    # RESERVED = 0x03.byte .. 0xFE.byte ## <-- would be nice to have
    NO_ACCEPTABLE_METHODS = 0xFF.byte
  AuthVersion* = enum
    AuthVersionV1 = 0x01.byte
  UserPasswordStatus* {.pure.} = enum
    SUCCEEDED = 0x00
    FAILED = 0x01
  SocksCmd* {.pure.} = enum
    CONNECT = 0x01.byte
    BIND = 0x02.byte
    UDP_ASSOCIATE = 0x03.byte
  ATYP* = enum
    IP_V4_ADDRESS = 0x01.byte
    DOMAINNAME = 0x03.byte
    IP_V6_ADDRESS = 0x04.byte
  REP* = enum
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
    socksVersion*: byte

  # Socks5
  SocksRequest* = ref object
    version*: SOCKS_VERSION
    cmd*: byte
    rsv*: byte
    atyp*: ATYP
    dst_addr*: seq[byte]
    dst_port*: tuple[h: byte, l: byte]
  SocksResponse* = ref object
    version*: SOCKS_VERSION
    rep*: byte
    rsv*: byte
    atyp*: ATYP
    bnd_addr*: seq[byte]
    bnd_port*: tuple[h: byte, l: byte]
  SocksUserPasswordRequest* = ref object
    authVersion*: byte
    ulen*: byte
    uname*: seq[byte]
    plen*: byte
    passwd*: seq[byte]
  SocksUserPasswordResponse* = ref object
   authVersion*: byte
   status*: byte

  ## Socks4 & Socks4a
  REP4* = enum
    REQUEST_GRANTED = 0x5A.byte
    REQUEST_REJECTED_OR_FAILED = 0x05B.byte
  Socks4Cmd* {.pure.} = enum
    CONNECT = 0x01.byte
    BIND = 0x02.byte
  Socks4Request* = ref object
    socksVersion*: byte # socksVersion*: SOCKS_VERSION
    cmd*: byte # cmd*: Socks4Cmd
    dst_port*: tuple[h: byte, l: byte]
    dst_ip*: seq[byte] # 4 byte array! # TODO
    userid*: seq[byte] # null terminated but not captured!
    # socksDns*: seq[byte]
  Socks4Response* = ref object
    socks4ReplyVersion*: byte
    cmd*: byte
    dst_port*: tuple[h: byte, l: byte]
    dst_ip*: seq[byte] # 4 byte array! # TODO

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
  result.add obj.cmd.char
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
  result.cmd = cmd.byte
  result.rsv = RESERVED.byte
  (result.atyp, result.dst_addr) = address.parseHost()
  result.dst_port = port.unPort()

proc newSocksResponse*(socksRequest: SocksRequest, rep: REP): SocksResponse =
  result = SocksResponse()
  result.version = socksRequest.version
  result.rep = rep.byte
  result.rsv = RESERVED.byte
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
  result.authVersion = AuthVersionV1.byte
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

proc recvByte*(client: AsyncSocket): Future[byte] {.async.} =
  # return (await client.recv(1))[0].byte # crash 18.1
  var dat = await client.recv(1) # TODO remove workaround someday
  return dat[0].byte

proc recvBytes*(client: AsyncSocket, count: int): Future[seq[byte]] {.async.} =
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
    obj.authVersion = await client.recvByte
    if obj.authVersion != AuthVersionV1.byte: return false

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
    obj.version = (await client.recvByte).SOCKS_VERSION

    obj.cmd = await client.recvByte
    if not inEnum[SocksCmd](obj.cmd): return false

    obj.rsv = await client.recvByte
    if obj.rsv != RESERVED.byte: return false

    obj.atyp = (await client.recvByte).ATYP
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

proc recvSocksResponse*(client:AsyncSocket, obj: SocksResponse): Future[bool] {.async.} =
  try:
    obj.version = (await client.recvByte).SOCKS_VERSION

    obj.rep = await client.recvByte
    if not inEnum[REP](obj.rep): return false

    obj.rsv = await client.recvByte
    if obj.rsv != RESERVED.byte: return false

    obj.atyp = (await client.recvByte).ATYP

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


proc recvResponseMessageSelection*(client:AsyncSocket, obj: ResponseMessageSelection): Future[bool] {.async.} =
  try:
    obj.version = (await client.recvByte).SOCKS_VERSION
  except:
    return false

  try:
    obj.selectedMethod = (await client.recvByte).AuthenticationMethod
  except:
    return false

  return true


proc recvSocksUserPasswordResponse*(client:AsyncSocket, obj: SocksUserPasswordResponse): Future[bool] {.async.} =
  try:
    obj.authVersion = await client.recvByte
  except:
    dbg "recvSocksUserPasswordResponse failed"
    return false
  if obj.authVersion != AuthVersionV1.byte: return false
  obj.status = await client.recvByte
  if not inEnum[UserPasswordStatus](obj.status): return false
  return true

proc recvSocksVersion*(client:AsyncSocket, socksVersionRef: SocksVersionRef): Future[bool] {.async.} =
  try:
    socksVersionRef.socksVersion = await client.recvByte
  except:
    dbg "recvSocksVersion failed"
    return false
  if not inEnum[SOCKS_VERSION](socksVersionRef.socksVersion): return false
  return true

proc recvSocks4Request*(client:AsyncSocket, obj: Socks4Request): Future[bool] {.async.} =
  obj.socksVersion = SOCKS_V4.byte
  try:
    obj.cmd = await client.recvByte
    if not inEnum[SocksCmd](obj.cmd): return false
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
  result.cmd = rep.byte
  result.dst_ip = @[0.byte,0.byte,0.byte,0.byte] # ignored
  result.dst_port = (0.byte,0.byte) # ignored

proc isSocks4aHack*(dst_ip: seq[byte]): bool =
  return
    dst_ip[0] == NULL and
    dst_ip[1] == NULL and
    dst_ip[2] == NULL and
    dst_ip[3] != NULL
