discard """
  action: "run"
  batchable: false
  joinable: false
  target: "c cpp"
"""

# TODO test socks 4 and 4a

## Tests if client and server compiles, and if the client can send data back and forth
## through the proxy, with its default configuration (the client can only do socks5 at the moment)

import asyncdispatch, asyncnet
import ../../nimSocks/server
import ../../nimSocks/client

const
  HOST* = "127.0.0.1"
  PROXY_PORT* = 1081
  SERVER_TEST_PORT* = 8908
  USERNAME* = "hans"
  PASSWORD* = "peter"
  TST1* = "TEST"
  TST2* = "TEST2"

proc tproxy*(pw = false): Future[SocksServer] {.async.} =
  var proxy = newSocksServer(listenPort = PROXY_PORT.Port)
  proxy.allowedSocksVersions = {SOCKS_V4, SOCKS_V5}
  proxy.allowedAuthMethods = {NO_AUTHENTICATION_REQUIRED}
  if pw:
    proxy.allowedAuthMethods.incl USERNAME_PASSWORD
    proxy.addUser(USERNAME, PASSWORD)
  proxy.shouldLogHost = false
  asyncCheck proxy.serve()
  return proxy

proc tclient*(pw = false): Future[AsyncSocket] {.async.} =
  result = await asyncnet.dial(HOST, PROXY_PORT.Port)
  if pw:
    doAssert true == await result.doSocksHandshake(username = USERNAME, password = PASSWORD)
  else:
    doAssert true == await result.doSocksHandshake()
  doAssert true == await result.doSocksConnect(HOST, SERVER_TEST_PORT.Port)

proc tserver*(): Future[AsyncSocket] {.async.} =
  result = newAsyncSocket()
  result.setSockOpt(OptReuseAddr, true)
  result.setSockOpt(OptReusePort, true)
  result.bindAddr(SERVER_TEST_PORT.Port, HOST)
  result.listen()

proc test(pw = false) {.async.} =
  var proxy = await tproxy(pw)
  var server = await tserver()
  var client = await tclient(pw = pw)
  var clientSock = await server.accept()

  # Client ---> socks ---> server
  asyncCheck client.send(TST1 & "\n")
  doAssert TST1 == await clientSock.recvLine()

  # server ---> socks ---> client
  asyncCheck clientSock.send(TST2 & "\n")
  doAssert TST2 == await client.recvLine()
  quit(0)

when isMainModule:
  waitFor test()
  waitFor test(pw = true)