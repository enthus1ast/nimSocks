import types, net, asyncnet, tables, nimSHA2, byteCounter, domainfilter, sets, hashes
export types, net, asyncnet, tables, nimSHA2, byteCounter, domainfilter, sets, hashes
const
  SIZE* = 87_380 ## max size the buffer could be
              ## but since we peek on the sockets,
              ## this buffer gets not filled completely
              ## anyway...
  STALLING_TIMEOUT* = 250 # when full: wait then try again
type SocksServer* = ref object
  listenPort*: Port
  listenHost*: string
  blacklistHost*: HashSet[Hash]
  blacklistHostFancy*: seq[BlacklistEntry]
  whitelistHost*: HashSet[Hash]
  whitelistHostFancy*: seq[BlacklistEntry]
  serverSocket*: AsyncSocket
  staticHosts*: Table[string, string]
  shouldLogHost*: bool
  logFile*: File
  logFileReverse*: File
  users*: TableRef[string, SHA512Digest]
  allowedAuthMethods*: set[AuthenticationMethod]
  allowedSocksCmds*: set[SocksCmd]
  allowedSocksVersions*: set[SOCKS_VERSION]
  prohibitPrivate*: bool
  stallingTimeout*: int
  byteCounter*: ByteCounter