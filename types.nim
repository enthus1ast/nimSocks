const
  SOCKS_V4* = 0x04.byte
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

proc newSocksResponse*(socksRequest: SocksRequest, rep: REP): SocksResponse =
  result = SocksResponse()
  result.version = socksRequest.version
  result.rep = rep.byte
  result.rsv = 0x00.byte
  result.atyp = socksRequest.atyp