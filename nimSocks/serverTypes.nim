import types,net,asyncnet,tables,nimSHA2,byteCounter,domainfilter
export types,net,asyncnet,tables,nimSHA2,byteCounter,domainfilter
const
  SIZE* = 87_380 ## max size the buffer could be
              ## but since we peek on the sockets,
              ## this buffer gets not filled completely
              ## anyway...
  # SIZE = 6291456
  STALLING_TIMEOUT* = 250 # when full: wait then try again
  # ENABLE_MONITORING = true # enables the throughput monitoring
type SocksServer* = ref object
  listenPort*: Port
  listenHost*: string
  blacklistHost*: seq[string]
  blacklistHostFancy*: seq[BlacklistEntry]
  whitelistHost*: seq[string]
  whitelistHostFancy*: seq[BlacklistEntry]
  serverSocket*: AsyncSocket
  staticHosts*: Table[string, string]
  logFile*: File
  logFileReverse*: File
  users*: TableRef[string, SHA512Digest]
  allowedAuthMethods*: set[AuthenticationMethod]
  allowedSocksCmds*: set[SocksCmd]
  allowedSocksVersions*: set[SOCKS_VERSION]
  transferedBytes*: int
  # socks4Enabled*: bool
  # socks5Enabled*: bool
  stallingTimeout*: int
  byteCounter*: ByteCounter
  # tcpBindPortRange: range[int]