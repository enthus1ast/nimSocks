discard """
  action: "run"
  batchable: false
  joinable: false
  target: "c cpp"
"""

## Tests if client and server compiles, and if the client can send data back and forth
## through the proxy, with its default configuration (the client can only do socks5 at the moment)

import asyncdispatch, asyncnet
import ../../nimSocks/server
import ../../nimSocks/client

const
  HOST = "127.0.0.1"
  PROXY_PORT = 1080
  SERVER_TEST_PORT = 7755

  TST1 = "TEST"
  TST2 = "TEST2"

proc tproxy() {.async.} =
  var proxy = newSocksServer()
  proxy.allowedSocksVersions = {SOCKS_V4, SOCKS_V5}
  proxy.allowedAuthMethods = {USERNAME_PASSWORD, NO_AUTHENTICATION_REQUIRED}
  proxy.shouldLogHost = false
  asyncCheck proxy.serve()

proc tclient(): Future[AsyncSocket] {.async.} =
  result = await asyncnet.dial(HOST, PROXY_PORT.Port)
  doAssert true == await result.doSocksHandshake()
  doAssert true == await result.doSocksConnect(HOST, SERVER_TEST_PORT.Port)

proc tserver(): Future[AsyncSocket] {.async.} =
  result = newAsyncSocket()
  result.bindAddr(SERVER_TEST_PORT.Port, HOST)
  result.listen()

proc test() {.async.} =
  await tproxy()
  var server = await tserver()
  var client = await tclient()
  var clientSock = await server.accept()

  # Client ---> socks ---> server
  asyncCheck client.send(TST1 & "\n")
  doAssert TST1 == await clientSock.recvLine()

  # server ---> socks ---> client
  asyncCheck clientSock.send(TST2 & "\n")
  doAssert TST2 == await client.recvLine()
  quit(0)

waitFor test()