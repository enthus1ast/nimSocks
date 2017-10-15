import net, asyncnet, asyncdispatch

const
  SOCKS_V4* = 0x04.byte # same as 4a
  SOCKS_V5* = 0x05.byte
  DEFAULT_PORT* = 1080

type
  RequestMessageSelection* = object
    version*: byte
    methodsLen*: byte
    methods*: seq[byte]
  ResponseMessageSelection* = object
    version*: byte
    selectedMethod*: byte
  AuthenticationMethod* = enum
    NO_AUTHENTICATION_REQUIRED = 0x00.byte
    GSSAPI = 0x01.byte
    USERNAME_PASSWORD = 0x02.byte
    # to X'7F' IANA ASSIGNED = 0x03
    # to X'FE' RESERVED FOR PRIVATE METHODS = 0x80
    NO_ACCEPTABLE_METHODS = 0xFF.byte
  UserPasswordStatus* {.pure.} = enum
    SUCCEEDED = 0x00
    FAILED = 0x01
  SocksCmd* = enum
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
  SocksRequest* = object
    version*: byte
    cmd*: byte
    rsv*: byte
    atyp*: byte
    dst_addr*: seq[byte]
    dst_port*: tuple[h: byte, l: byte]
  SocksResponse* = object
    version*: byte
    rep*: byte
    rsv*: byte
    atyp*: byte
    bnd_addr*: seq[byte]
    bnd_port*: tuple[h: byte, l: byte]
  SocksUserPasswordRequest* = ref object
    authVersion*: byte
    ulen*: byte
    uname*: seq[byte]
    plen*: byte
    passwd*: seq[byte]
  SocksUserPasswordResponse* = object
   authVersion*: byte
   status*: byte

proc newSocksResponse*(socksRequest: SocksRequest, rep: REP): SocksResponse =
  result = SocksResponse()
  result.version = socksRequest.version
  result.rep = rep.byte
  result.rsv = 0x00.byte
  result.atyp = socksRequest.atyp

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
  # if obj.atyp.ATYP == DOMAINNAME:
  #   result.add obj.bnd_addr.len.char
  result.add $obj.bnd_addr
  result.add obj.bnd_port.h.char
  result.add obj.bnd_port.l.char

proc `$`*(obj: SocksUserPasswordResponse): string =
  result = ""
  result.add obj.authVersion.char
  result.add obj.status.char

proc `$`*(obj: seq[byte]): string =
  result = ""
  for ch in obj:
    result.add ch.char

proc toSeq*(str: string): seq[byte] = 
  result = @[]
  for ch in str:
    result.add ch.byte

proc parseDestAddress*(bytes: seq[byte], atyp: ATYP): string =
  result = ""
  for idx, ch in bytes:
    case atyp
    of DOMAINNAME:
      result.add(ch.chr())
    of IP_V4_ADDRESS: 
      result.add($ch)
      if idx != 3: result.add('.')
    of IP_V6_ADDRESS:
      result.add($ch)
      if idx != 15: result.add(':')

proc port*(t: tuple[h, l: byte]): Port =
  return Port(t.h.int * 256 + t.l.int)

proc unPort*(p: Port): tuple[h, l: byte] =
  return ((p.int div 256).byte, (p.int mod 256).byte)

proc recvByte*(client: AsyncSocket): Future[byte] {.async.} =
  return (await client.recv(1))[0].byte

proc recvBytes*(client: AsyncSocket, count: int): Future[seq[byte]] {.async.} =
  return (await client.recv(count)).toSeq()

proc toBytes*(str: string): seq[byte] =
  result = @[]
  for ch in str:
    result.add ch.byte

proc recvCString*(client: AsyncSocket): Future[seq[byte]] {.async.} =
  result = @[]
  var ch: byte
  while true:
    ch = await client.recvByte
    if ch == 0x00.byte: break
    result.add(ch.byte)

proc `in`*(bytesMethod: seq[byte], authMethods: set[AuthenticationMethod]): bool =
  for byteMethod in bytesMethod:
    if byteMethod.AuthenticationMethod in authMethods: return true
  return false

proc parseSocksUserPasswordReq*(client:AsyncSocket, obj: SocksUserPasswordRequest): Future[bool] {.async.} =
  obj.authVersion = await client.recvByte
  if obj.authVersion != 0x01.byte: return false

  obj.ulen = await client.recvByte
  if obj.ulen == 0x00: return false

  obj.uname = await client.recvBytes(obj.ulen.int)
  if obj.uname.len == 0: return false

  obj.plen = await client.recvByte
  if obj.plen == 0x00: return false

  obj.passwd = await client.recvBytes(obj.plen.int)
  if obj.passwd.len == 0: return false

  return true

# proc `in`*(authMethod: AuthenticationMethod, bytesMethod: seq[byte]): bool =
#   return authMethod.byte in bytesMethod
