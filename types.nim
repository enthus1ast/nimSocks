import net, asyncnet, asyncdispatch, strutils

const
  DEFAULT_PORT* = 1080

type
  SOCKS_VERSION* = enum
    # SOCKS_V4 = 0x04.byte # same as 4a
    SOCKS_V5 = 0x05.byte
  RequestMessageSelection* = ref object
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
  SocksRequest* = ref object
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

proc toSeq*(obj: set[AuthenticationMethod]): seq[byte] =
  result = @[]
  for ch in obj:
    result.add ch.byte

proc newSocksResponse*(socksRequest: SocksRequest, rep: REP): SocksResponse =
  result = SocksResponse()
  result.version = socksRequest.version
  result.rep = rep.byte
  result.rsv = 0x00.byte
  result.atyp = socksRequest.atyp

proc newRequestMessageSelection*(version: SOCKS_VERSION, methods: set[AuthenticationMethod]): RequestMessageSelection =
  result = RequestMessageSelection()
  result.version = version.byte
  result.methodsLen = methods.toSeq().len.byte
  result.methods = methods.toSeq()

proc newResponseMessageSelection*(version: SOCKS_VERSION, selectedMethod: AuthenticationMethod): ResponseMessageSelection =
  result = ResponseMessageSelection()
  result.version = version.byte
  result.selectedMethod = selectedMethod.byte

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

proc recvSocksUserPasswordReq*(client:AsyncSocket, obj: SocksUserPasswordRequest): Future[bool] {.async.} =
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

# proc `in`*(bt: byte, obj: SOCKS_VERSION): bool =
#   for en in obj:
#     echo en
proc parseEnum[T](bt: byte): T =
  for elem in T:
    if bt.T == elem: 
      return bt.T
  raise newException(ValueError, "invalid byte")

proc inEnum[T](bt: byte): bool =
  try:
    discard parseEnum[T](bt)
    return true
  except:
    return false

proc recvSocksReq*(client:AsyncSocket, obj: SocksRequest): Future[bool] {.async.} =
  obj.version = await client.recvByte
  if not inEnum[SOCKS_VERSION](obj.version): return false

  obj.cmd = await client.recvByte
  if not inEnum[SocksCmd](obj.cmd): return false

  obj.rsv = await client.recvByte 
  if obj.rsv != 0x00.byte: return false

  obj.atyp = await client.recvByte
  if not inEnum[ATYP](obj.atyp): return false

  obj.dst_addr = case obj.atyp.ATYP
    of IP_V4_ADDRESS: await client.recvBytes(4)
    of DOMAINNAME: await client.recvBytes((await client.recvByte).int)
    of IP_V6_ADDRESS: await client.recvBytes(16)
  
  obj.dst_port = (await client.recvByte, await client.recvByte) # *: tuple[h: byte, l: byte]

  return true


proc recvRequestMessageSel*(client:AsyncSocket, obj: RequestMessageSelection): Future[bool] {.async.} =
  obj.version = await client.recvByte
  if not inEnum[SOCKS_VERSION](obj.version):  return false

  obj.methodsLen = await client.recvByte
  if obj.methodsLen < 1: return false

  obj.methods = await client.recvBytes(obj.methodsLen.int)

  return true