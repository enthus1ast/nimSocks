import net, asyncnet, asyncdispatch, strutils

const
  DEFAULT_PORT* = 1080
  RESERVED = 0x00.byte

type
  SOCKS_VERSION* = enum
    # SOCKS_V4 = 0x04.byte # same as 4a
    SOCKS_V5 = 0x05.byte
  RequestMessageSelection* = ref object
    version*: byte
    methodsLen*: byte
    methods*: seq[byte]
  ResponseMessageSelection* = ref object
    version*: byte
    selectedMethod*: byte
  AuthenticationMethod* = enum
    NO_AUTHENTICATION_REQUIRED = 0x00.byte
    GSSAPI = 0x01.byte
    USERNAME_PASSWORD = 0x02.byte
    # to X'7F' IANA ASSIGNED = 0x03
    # to X'FE' RESERVED FOR PRIVATE METHODS = 0x80
    NO_ACCEPTABLE_METHODS = 0xFF.byte
  AuthVersion* = enum
    AuthVersionV1 = 0x01.byte
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
  SocksResponse* = ref object
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
  SocksUserPasswordResponse* = ref object
   authVersion*: byte
   status*: byte

proc toBytes*(str: string): seq[byte] =
  result = @[]
  for ch in str:
    result.add ch.byte

proc toBytes*(arr: openarray[uint8]): seq[byte] =
  ## for converting ip
  result = @[]
  for el in arr:
    result.add el.byte

proc `in`*(bytesMethod: seq[byte], authMethods: set[AuthenticationMethod]): bool =
  for byteMethod in bytesMethod:
    if byteMethod.AuthenticationMethod in authMethods: return true
  return false

proc `$`*(obj: seq[byte]): string =
  result = ""
  for ch in obj:
    result.add ch.char

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
  result.add $obj.bnd_addr
  result.add obj.bnd_port.h.char
  result.add obj.bnd_port.l.char

proc `$`*(obj: SocksRequest): string =
  result = ""
  result.add obj.version.char 
  result.add obj.cmd.char 
  result.add obj.rsv.char 
  result.add obj.atyp.char 
  result.add $obj.dst_addr
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
  result.add $obj.methods

proc `$`*(obj: SocksUserPasswordRequest): string =
  result = ""
  result.add obj.authVersion.char 
  result.add obj.ulen.char 
  result.add $obj.uname
  result.add obj.plen.char 
  result.add $obj.passwd

proc toSeq*(str: string): seq[byte] = 
  result = @[]
  for ch in str:
    result.add ch.byte

proc toSeq*(obj: set[AuthenticationMethod]): seq[byte] =
  result = @[]
  for ch in obj:
    result.add ch.byte

proc port*(t: tuple[h, l: byte]): Port =
  return Port(t.h.int * 256 + t.l.int)

proc unPort*(p: Port): tuple[h, l: byte] =
  return ((p.int div 256).byte, (p.int mod 256).byte)

proc newSocksRequest*(
  cmd: SocksCmd, 
  address: string, 
  port: Port, 
  socksVersion: SOCKS_VERSION = SOCKS_V5
): SocksRequest =

  if address.len == 0: raise newException(ValueError, "address should not be empty")
  result = SocksRequest()
  result.version  = socksVersion.byte
  result.cmd = cmd.byte
  result.rsv = 0x00.byte
  var ipaddr: IpAddress
  try:
    ipaddr = address.parseIpAddress()
    case ipaddr.family
    of IPv4:
      echo "IPv4"
      result.atyp = IP_V4_ADDRESS.byte
      result.dst_addr = ipaddr.address_v4.toBytes()
      
    of IPv6:
      echo "IPv6"
      result.atyp = IP_V6_ADDRESS.byte 
      result.dst_addr = ipaddr.address_v6.toBytes()
  except:
      echo "DOMAINNAME"
      result.atyp = DOMAINNAME.byte
      result.dst_addr = address.len.byte & address.toBytes()
      
  result.dst_port = port.unPort()
  echo repr result

proc newSocksResponse*(socksRequest: SocksRequest, rep: REP): SocksResponse =
  result = SocksResponse()
  result.version = socksRequest.version
  result.rep = rep.byte
  result.rsv = RESERVED.byte
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

proc newSocksUserPasswordRequest*(username: string, password: string): SocksUserPasswordRequest =
  result = SocksUserPasswordRequest()
  result.authVersion = AuthVersionV1.byte #default auth version!
  result.ulen = username.len.byte #*: byte
  result.uname = username.toBytes() #*: seq[byte]
  result.plen =  password.len.byte #*: byte
  result.passwd =  password.toBytes() #*: seq[byte]

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

proc recvByte*(client: AsyncSocket): Future[byte] {.async.} =
  return (await client.recv(1))[0].byte

proc recvBytes*(client: AsyncSocket, count: int): Future[seq[byte]] {.async.} =
  return (await client.recv(count)).toSeq()

proc recvSocksUserPasswordRequest*(client:AsyncSocket, obj: SocksUserPasswordRequest): Future[bool] {.async.} =
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

  return true

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

proc recvSocksRequest*(client:AsyncSocket, obj: SocksRequest): Future[bool] {.async.} =
  obj.version = await client.recvByte
  if not inEnum[SOCKS_VERSION](obj.version): return false

  obj.cmd = await client.recvByte
  if not inEnum[SocksCmd](obj.cmd): return false

  obj.rsv = await client.recvByte 
  if obj.rsv != RESERVED.byte: return false

  obj.atyp = await client.recvByte
  if not inEnum[ATYP](obj.atyp): return false

  obj.dst_addr = case obj.atyp.ATYP
    of IP_V4_ADDRESS: await client.recvBytes(4)
    of DOMAINNAME: await client.recvBytes((await client.recvByte).int)
    of IP_V6_ADDRESS: await client.recvBytes(16)
  
  obj.dst_port = (await client.recvByte, await client.recvByte) # *: tuple[h: byte, l: byte]
  return true

proc recvSocksResponse*(client:AsyncSocket, obj: SocksResponse): Future[bool] {.async.} =
  obj.version = await client.recvByte
  if not inEnum[SOCKS_VERSION](obj.version): return false

  obj.rep = await client.recvByte
  if not inEnum[REP](obj.rep): return false

  obj.rsv = await client.recvByte 
  if obj.rsv != RESERVED.byte: return false

  obj.atyp = await client.recvByte
  if not inEnum[ATYP](obj.atyp): return false

  obj.bnd_addr = case obj.atyp.ATYP
    of IP_V4_ADDRESS: await client.recvBytes(4)
    of DOMAINNAME: await client.recvBytes((await client.recvByte).int)
    of IP_V6_ADDRESS: await client.recvBytes(16)
  
  obj.bnd_port = (await client.recvByte, await client.recvByte) # *: tuple[h: byte, l: byte]
  return true    

proc recvRequestMessageSelection*(client:AsyncSocket, obj: RequestMessageSelection): Future[bool] {.async.} =
  obj.version = await client.recvByte
  if not inEnum[SOCKS_VERSION](obj.version): return false

  obj.methodsLen = await client.recvByte
  if obj.methodsLen < 1: return false

  obj.methods = await client.recvBytes(obj.methodsLen.int)

  return true

proc recvResponseMessageSelection*(client:AsyncSocket, obj: ResponseMessageSelection): Future[bool] {.async.} =
  obj.version = await client.recvByte
  if not inEnum[SOCKS_VERSION](obj.version): return false

  obj.selectedMethod = await client.recvByte
  return true


proc recvSocksUserPasswordResponse*(client:AsyncSocket, obj: SocksUserPasswordResponse): Future[bool] {.async.} =
  obj.authVersion = await client.recvByte 
  if obj.authVersion != AuthVersionV1.byte: return false  

  obj.status = await client.recvByte
  if not inEnum[UserPasswordStatus](obj.status): return false 
  return true
