#
#
#                  nimSocks
#          SOCKS4/4a/5 proxy server
#            (c) Copyright 2020
#        David Krause, Tobias Freitag
#
#    See the file "LICENSE", included in this
#    distribution, for details about the copyright.
#
## SOCKS4/4a/5 proxy server

import asyncdispatch, asyncnet, nativesockets, tables, dbg
import reverseDomainNotation
import pump
import byteCounter
import isPrivateIp

import serverTypes
export serverTypes

proc newSocksServer*(
    listenPort: Port = Port(DEFAULT_PORT),
    listenHost: string = "",
    allowedAuthMethods: set[AuthenticationMethod] = {USERNAME_PASSWORD},
    allowedSocksVersions: set[SOCKS_VERSION] = {SOCKS_V4, SOCKS_V5},
): SocksServer =
  result = SocksServer()
  result.listenPort = listenPort
  result.listenHost = listenHost
  result.blacklistHostFancy = @[]
  result.whitelistHostFancy = @[]
  result.serverSocket = newAsyncSocket()
  result.staticHosts = initTable[string, string]()
  result.users = newTable[string, SHA512Digest]()
  result.allowedAuthMethods = allowedAuthMethods
  result.allowedSocksCmds = {SocksCmd.CONNECT}
  result.allowedSocksVersions = allowedSocksVersions
  result.stallingTimeout = STALLING_TIMEOUT
  result.byteCounter = newByteCounter()

proc isBlacklisted(proxy: SocksServer, host: string): bool =
  return proxy.blacklistHost.isListed(host) or proxy.blacklistHostFancy.isListed(host)

proc isWhitelisted(proxy: SocksServer, host: string): bool =
  return proxy.whitelistHost.isListed(host) or proxy.whitelistHostFancy.isListed(host)

proc isListed(proxy: SocksServer, host: string): bool =
  if proxy.prohibitPrivate:
    if host.isPrivate(): return true
  if proxy.whitelistHost.len == 0 and proxy.whitelistHostFancy.len == 0:
    if proxy.isBlacklisted(host):
      echo "Blacklisted host:", host
      return true
  else:
    if not proxy.isWhitelisted(host):
      echo "Not whitelisted host:", host
      return true

proc authenticate(proxy: SocksServer, username, password: string): bool =
  result = false
  dbg "username: ", username
  dbg "password: ", password
  if username.len == 0: return
  if password.len == 0: return
  if not proxy.users.hasKey(username):
    dbg "user unknown: ", username
    return false

  var
    hashedPassword = initSHA[SHA512]()
    hashFromDb = proxy.users[username]

  hashedPassword.update(username)
  hashedPassword.update(password)

  dbg "hashedPassword: ", hashedPassword
  dbg "hashFromDb: ", hashFromDb

  if hashedPassword.final() == hashFromDb:
    result = true

proc addUser*(proxy: SocksServer, username: string, password: string) =
  if proxy.users.hasKey(username): raise newException(ValueError, "User already exists.")
  if username.len == 0: raise newException(ValueError, "Username required.")
  if password.len == 0: raise newException(ValueError, "Password required.")

  var hashedPassword = initSHA[SHA512]()
  hashedPassword.update(username)
  hashedPassword.update(password)

  proxy.users[username] = hashedPassword.final()

proc logHost(proxy: SocksServer, host: string) =
  if not proxy.logFile.isNil:
    proxy.logFile.writeLine(host)
    proxy.logFile.flushFile()
  if not proxy.logFileReverse.isNil:
    proxy.logFileReverse.writeLine(host.reverseNotation() )
    proxy.logFileReverse.flushFile()

proc getStaticRewrite(proxy: SocksServer, host: string): string =
  if proxy.staticHosts.contains host:
    return proxy.staticHosts[host]
  return host

proc handleSocks5Connect(
  proxy: SocksServer,
  client: AsyncSocket,
  socksReq: SocksRequest
): Future[(bool, AsyncSocket)] {.async.} =
  var
    host = socksReq.dst_addr.parseDestAddress(socksReq.atyp)
    remoteSocket: AsyncSocket

  dbg "host: ", host
  dbg "hosR: ", repr(host)
  dbg "--->: ", host.reverseNotation()
  host = proxy.getStaticRewrite(host)
  if proxy.isListed(host):
      dbg "CONNECTION_NOT_ALLOWED_BY_RULESET"
      var socksResp = newSocksResponse(socksReq, CONNECTION_NOT_ALLOWED_BY_RULESET)
      await client.send($socksResp)
      return (false, nil)

  if proxy.shouldLogHost:
    proxy.logHost host

  var connectSuccess = true
  try:
    remoteSocket =  await asyncnet.dial(host, socksReq.dst_port.port())
  except:
    connectSuccess = false
  if not connectSuccess:
    var socksResp = newSocksResponse(socksReq, HOST_UNREACHABLE)
    await client.send($socksResp)
    echo "HOST_UNREACHABLE:", host
    return (false, nil)
  return (true, remoteSocket)


proc processSocks5(proxy: SocksServer, client: AsyncSocket): Future[bool] {.async.} =
  # Handshake/Authentication
  result = false
  var reqMessageSelection = RequestMessageSelection()
  if (await client.recvRequestMessageSelection(reqMessageSelection)) == false:
    dbg "could not parse RequestMessageSelection: ", reqMessageSelection.version
    return
  var respMessageSelection = ResponseMessageSelection()
  respMessageSelection.version = reqMessageSelection.version

  # Check if authentication method is supported and allowed by server
  if not (reqMessageSelection.methods in proxy.allowedAuthMethods):
    respMessageSelection.selectedMethod = NO_ACCEPTABLE_METHODS
    await client.send($respMessageSelection)
    return

  # Chose authentication methods
  if USERNAME_PASSWORD in reqMessageSelection.methods:
    dbg "Got user password Authentication"
    respMessageSelection.selectedMethod = USERNAME_PASSWORD
    await client.send($respMessageSelection)

    var socksUserPasswordReq = SocksUserPasswordRequest()
    if (await client.recvSocksUserPasswordRequest(socksUserPasswordReq)) == false:
      dbg "return from recvSocksUserPasswordRequest"
      return

    var socksUserPasswordResp = SocksUserPasswordResponse()
    socksUserPasswordResp.authVersion = AuthVersionV1
    if proxy.authenticate($socksUserPasswordReq.uname, $socksUserPasswordReq.passwd):
      socksUserPasswordResp.status = UserPasswordStatus.SUCCEEDED
      dbg "Sending good: ", repr($socksUserPasswordResp)
      await client.send($socksUserPasswordResp)
    else:
      socksUserPasswordResp.status = UserPasswordStatus.FAILED
      dbg "Sending bad: ", repr($socksUserPasswordResp)
      await client.send($socksUserPasswordResp)
      return

  elif NO_AUTHENTICATION_REQUIRED in reqMessageSelection.methods:
    respMessageSelection.selectedMethod = NO_AUTHENTICATION_REQUIRED
    await client.send($respMessageSelection)
  else:
    dbg "Not supported authentication method"
    return

  var socksReq = SocksRequest()
  if (await client.recvSocksRequest(socksReq)) == false:
    dbg "Could not parse socksReq"
    return

  var
    remoteSocket: AsyncSocket = nil
    handleCmdSucceed: bool = false
  if socksReq.cmd.SocksCmd notin proxy.allowedSocksCmds:
    dbg "proxy command not allowed"
    return
  case socksReq.cmd.SocksCmd:
    of SocksCmd.CONNECT:
      dbg "socks5 connect"
      (handleCmdSucceed, remoteSocket) = await proxy.handleSocks5Connect(client, socksReq)
    of SocksCmd.BIND:
      echo "BIND not implemented"
      # (handleCmdSucceed, remoteSocket) = await proxy.handleSocks5Bind(client, socksReq)
      return
    of SocksCmd.UDP_ASSOCIATE:
      echo "UDP_ASSOCIATE not implemented"
      return

  if handleCmdSucceed == false:
    dbg "Handling command: failed"
    return
  dbg "Handling command: succeed"

  var
    socksResp = newSocksResponse(socksReq, REP.SUCCEEDED)
    (hst, prt) = remoteSocket.getFd.getLocalAddr(Domain.AF_INET)

  ## BUG
  # the bind address is wrong!!
  #
  # https://tools.ietf.org/html/rfc1928
  # 5.  Addressing

  #  In an address field (DST.ADDR, BND.ADDR), the ATYP field specifies
  #  the type of address contained within the field:

  #         o  X'01'

  #  the address is a version-4 IP address, with a length of 4 octets

  #         o  X'03'

  #  the address field contains a fully-qualified domain name.  The first
  #  octet of the address field contains the number of octets of name that
  #  follow, there is no terminating NUL octet.

  #         o  X'04'
  # socksResp.bnd_addr = @[hst.len.byte]
  # socksResp.bnd_addr &= hst.toBytes()
  # socksResp.bnd_port = prt.unPort
  # echo "=1==============="
  # echo socksResp
  # echo "=2==============="
  # echo repr socksResp
  # echo "=3==============="
  # echo $socksResp
  # echo "================"
  await client.send($socksResp)

  # From here on we start relaying data
  asyncCheck pump(proxy.byteCounter, remoteSocket, client, downstream , socksReq.dst_addr, socksReq.atyp.ATYP)
  asyncCheck pump(proxy.byteCounter, client, remoteSocket, upstream   , socksReq.dst_addr, socksReq.atyp.ATYP)
  return true


proc handleSocks4Connect(
  proxy: SocksServer,
  client: AsyncSocket,
  socksReq: Socks4Request
): Future[(bool, AsyncSocket)] {.async.} =
  var
    host = socksReq.dst_ip.parseDestAddress(IP_V4_ADDRESS)
    remoteSocket: AsyncSocket

  dbg "host: ", host
  dbg "--->: ", host.reverseNotation()
  if socksReq.dst_ip.isSocks4aHack():
    dbg "socks4a"
    host = (await client.recvNullTerminated()).parseDestAddress(DOMAINNAME)
    dbg "REALHOST:",host

  host = proxy.getStaticRewrite(host)
  if proxy.isListed(host):
    dbg "REQUEST_REJECTED_OR_FAILED"
    var socksResp = newSocks4Response(REQUEST_REJECTED_OR_FAILED)
    await client.send($socksResp)
    return (false, nil)

  if proxy.shouldLogHost:
    proxy.logHost(host)

  var connectSuccess = true
  try:
    remoteSocket =  await asyncnet.dial(host, socksReq.dst_port.port())
  except:
    dbg "DIAL FAILED"
    dbg getCurrentExceptionMsg()
    connectSuccess = false

  if not connectSuccess:
    var socksResp = newSocks4Response(REQUEST_REJECTED_OR_FAILED)
    await client.send($socksResp)
    echo "HOST_UNREACHABLE:", host
    return (false, nil)

  return (true, remoteSocket)

proc processSocks4(proxy: SocksServer, client: AsyncSocket): Future[bool] {.async.} =
  result = false
  dbg "socks4"

  if not proxy.allowedAuthMethods.contains(NO_AUTHENTICATION_REQUIRED):
    dbg "socks4 socks4a does not support authentication, ensure that allowedAuthMethods contains NO_AUTHENTICATION_REQUIRED"
    return

  var socks4Request = Socks4Request()
  if (await client.recvSocks4Request(socks4Request)) == false:
    dbg "could not parse Socks4Request: " #, socks4Request
    return

  var
    remoteSocket: AsyncSocket = nil
    handleCmdSucceed: bool = false
  if socks4Request.cmd.SocksCmd notin proxy.allowedSocksCmds:
    dbg "proxy command not allowed"
    return
  case socks4Request.cmd.Socks4Cmd
  of Socks4Cmd.CONNECT:
    (handleCmdSucceed, remoteSocket) = await proxy.handleSocks4Connect(client, socks4Request)
  of Socks4Cmd.BIND:
    echo "BIND not implemented"
    return

  if handleCmdSucceed == false:
    dbg "Handling command: failed"
    return
  dbg "Handling command: succeed"

  var socksResp = newSocks4Response(REQUEST_GRANTED)
  await client.send($socksResp)

  # From here on we start relaying data
  asyncCheck pump(proxy.byteCounter, remoteSocket, client, downstream , socks4Request.dst_ip, ATYP.IP_V4_ADDRESS)
  asyncCheck pump(proxy.byteCounter, client, remoteSocket, upstream   , socks4Request.dst_ip, ATYP.IP_V4_ADDRESS)
  return true


proc processClient(proxy: SocksServer, client: AsyncSocket): Future[void] {.async.} =
  # Check for socks version.
  var socksVersionRef = SocksVersionRef()
  if (await client.recvSocksVersion(socksVersionRef)) == false:
    dbg "unknown socks version: ", socksVersionRef.socksVersion
    client.close()
    return

  var stayOpen: bool = false
  if socksVersionRef.socksVersion.SOCKS_VERSION notin proxy.allowedSocksVersions:
    dbg "socket version not allowed"
    client.close()
    return

  case socksVersionRef.socksVersion.SOCKS_VERSION
  of SOCKS_V4:
    stayOpen = await proxy.processSocks4(client)
  of SOCKS_V5:
    stayOpen = await proxy.processSocks5(client)

  if not client.isClosed and not stayOpen:
    client.close()



proc serve*(proxy: SocksServer): Future[void] {.async.} =
  proxy.serverSocket.setSockOpt(OptReusePort, true)
  # proxy.serverSocket.getFd.setSockOptInt(SOL_SOCKET.cint, )
  proxy.serverSocket.setSockOpt(OptNoDelay, true) # TODO test if this is good
  # proxy.serverSocket.setSockOpt(TCP_QUICKACK, true)
  proxy.serverSocket.bindAddr(proxy.listenPort, proxy.listenHost)
  proxy.serverSocket.listen()
  var
    address: string
    client: AsyncSocket
    stalling: bool = false
  while true:
    if stalling: await sleepAsync(proxy.stallingTimeout)
    try:
      (address, client) = await proxy.serverSocket.acceptAddr()
      echo "connection from: ", address
      stalling = false
    except:
      dbg "could not accept new connection:"
      dbg getCurrentExceptionMsg()
      stalling = true
      continue

    client.setSockOpt(OptNoDelay, true) # TODO test if this is good
    client.setSockOpt(OptReuseAddr, true)
    asyncCheck proxy.processClient(client)

when not defined release:
  block:
    var proxy = newSocksServer()
    proxy.addUser("hans", "peter")
    assert proxy.authenticate("hans", "peter") == true
    assert proxy.authenticate(" hans", "peter") == false
    assert proxy.authenticate("hans", "peter ") == false
    assert proxy.authenticate(" hans", "peter ") == false
    assert proxy.authenticate("as hans", "dd cpeter ") == false

when isMainModule:
  import throughput, os
  var proxy = newSocksServer()
  echo "SOCKS Proxy listens on: ", proxy.listenPort

  ## Socks 4 has no authentication
  # proxy.allowedSocksVersions = {SOCKS_V4}
  # proxy.allowedAuthMethods = {NO_AUTHENTICATION_REQUIRED}

  ## Socks 5 has authentication!
  proxy.allowedSocksVersions = {SOCKS_V4, SOCKS_V5}
  proxy.allowedAuthMethods = {USERNAME_PASSWORD, NO_AUTHENTICATION_REQUIRED}

  ## Prohibit proxy to reach private ips
  proxy.prohibitPrivate = true

  ## If the proxy server should log hosts
  proxy.shouldLogHost = false
  if proxy.shouldLogHost:
    proxy.logFile = open("hosts.txt", fmAppend)
    proxy.logFileReverse = open("hostsReverse.txt", fmAppend)

  ## Add a valid user / password combination
  proxy.addUser("hans", "peter")

  ## Download blacklist, !! this overwrites the old list !!
  # import httpclient
  # let blacklistUrl = "https://raw.githubusercontent.com/notracking/hosts-blocklists/master/dnscrypt-proxy/dnscrypt-proxy.blacklist.txt"
  # var client = newHttpClient()
  # writeFile(getAppDir() / "blacklist.txt", client.getContent(blacklistUrl))

  ## Files for black and whitelisting
  proxy.blacklistHost = loadList(getAppDir() / "blacklist.txt")
  # proxy.blacklistHostFancy = loadListFancy("blacklistFancy.txt")
  # proxy.whitelistHostFancy = loadListFancy("whitelistFancy.txt")
  # proxy.whitelistHost = @[
  #   "example.org"
  # ]

  ## For a static host replacement:
  proxy.staticHosts["peter.peter"] = "ch4t.code0.xyz"

  asyncCheck proxy.serve()
  asyncCheck proxy.dumpThroughput()
  runForever()
