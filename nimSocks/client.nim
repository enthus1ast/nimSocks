#
#
#                  nimSocks
#          SOCKS4/4a/5 proxy server
#            (c) Copyright 2020
#        David Krause, Tobias Freitag
#
#    See the file "LICENSE", included in this
#    distribution, for details about the copyright.
## SOCKS4/4a/5 proxy client library

import net, asyncdispatch, asyncnet, nativesockets
import types

proc doSocksHandshake*(
  clientSocket: AsyncSocket | Socket,
  methods: set[AuthenticationMethod] = {NO_AUTHENTICATION_REQUIRED},
  username: string = "",
  password: string = "",
  version: SOCKS_VERSION = SOCKS_V5
): Future[bool] {.multisync.} =
  var req = newRequestMessageSelection(version, methods)
  await clientSocket.send($req)

  var respMsgSel = ResponseMessageSelection() #sever tells us which method to use
  if not (await clientSocket.recvResponseMessageSelection(respMsgSel) ):
    return false # could not parse

  case respMsgSel.selectedMethod.AuthenticationMethod
  of NO_AUTHENTICATION_REQUIRED:
    return true
  of USERNAME_PASSWORD:
    var socksUserPasswordRequest = newSocksUserPasswordRequest(username, password)
    await clientSocket.send($socksUserPasswordRequest)

    var socksUserPasswordResponse = SocksUserPasswordResponse()
    if not (await clientSocket.recvSocksUserPasswordResponse(socksUserPasswordResponse)):
      return false # could not parse

    if socksUserPasswordResponse.status.byte != REP.SUCCEEDED.byte:
      return false

    return true

  of NO_ACCEPTABLE_METHODS:
    return false
  else: return false


proc doSocksConnect*(clientSocket: AsyncSocket | Socket, targetHost: string, targetPort: Port) : Future[bool] {.multisync.} =
  var socksReq = newSocksRequest(SocksCmd.CONNECT, targetHost, targetPort)
  await clientSocket.send($socksReq)
  var socksResp = SocksResponse()
  if not (await clientSocket.recvSocksResponse(socksResp)): return false
  if socksResp.rep.byte != REP.SUCCEEDED.byte: return false
  return true

when isMainModule:
  import unittest

  proc sendHttp(sock: AsyncSocket | Socket): Future[string] {.multisync.} =
    # Then do normal socket operations
    var hh = """GET / HTTP/1.1
  Host: example.org

    """
    result = ""
    echo hh
    await sock.send(hh)
    var buf = ""
    while true:
      buf = await sock.recv(1)
      if buf == "": break
      write stdout, buf
      result.add buf
      buf.setLen 0



  suite "client":
    test "async":
      var sock = waitFor asyncnet.dial("127.0.0.1", Port 1080 ) # dial to the socks server
      assert true == waitFor sock.doSocksHandshake(
          username = "username",
          password = "password",
          version = SOCKS_V5,

          # the "best" auth supported gets choosen by the server!
          # methods={NO_AUTHENTICATION_REQUIRED, USERNAME_PASSWORD}
          methods={NO_AUTHENTICATION_REQUIRED}
          )

      # instruct the proxy to connect to target host (by tcp)
      assert true == waitFor sock.doSocksConnect("example.org", Port 80)
      # assert true == waitFor sock.doSocksConnect("127.0.0.1", Port 8000)

      echo "Send http..."

      check "" != waitFor sendHttp(sock)

    test "sync":

      var sock = net.dial("127.0.0.1", Port 1080 ) # dial to the socks server
      assert true == sock.doSocksHandshake(
      username = "username",
      password = "password",
      version = SOCKS_V5,

      # the "best" auth supported gets choosen by the server!
      # methods={NO_AUTHENTICATION_REQUIRED, USERNAME_PASSWORD}
      methods={NO_AUTHENTICATION_REQUIRED}
      )

      # instruct the proxy to connect to target host (by tcp)
      assert true == sock.doSocksConnect("example.org", Port 80)
      # assert true == waitFor sock.doSocksConnect("127.0.0.1", Port 8000)

      check "" != sendHttp(sock)
