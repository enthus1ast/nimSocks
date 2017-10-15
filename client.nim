import net, asyncdispatch, asyncnet, nativesockets
import types
import dbg

type SocksClient = object 
  # blacklistHost: seq[string]
  # blacklistHostFancy: seq[BlacklistEntry]
  # whitelistHost: seq[string]
  clientSocket: AsyncSocket
  # staticHosts: Table[string, string]
  # logFile: File
  # users: TableRef[string, SHA512Digest]
  allowedAuthMethods: set[AuthenticationMethod]

# proc newSocksClient(
#   clientSocket: AsyncSocket,
#   allowedAuthMethods: set[AuthenticationMethod] = {USERNAME_PASSWORD}
# ): Future[SocksClient] {.async.} =
#   result = SocksClient()
#   result.clientSocket = clientSocket
#   result.allowedAuthMethods = allowedAuthMethods


proc doSocksHandshake(
  clientSocket: AsyncSocket,
  methods: set[AuthenticationMethod] = {NO_AUTHENTICATION_REQUIRED},
  version: SOCKS_VERSION = SOCKS_V5
): Future[bool] {.async.} = 
  var req = newRequestMessageSelection(version, methods)
  await clientSocket.send($req)
  

  return true
proc doSocksConnect(clientSocket: AsyncSocket) : Future[bool] {.async.} =
  discard

when isMainModule:
  discard