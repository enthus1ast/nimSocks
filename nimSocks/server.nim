const
  SIZE = 87_380 ## max size the buffer could be
              ## but since we peek on the sockets,
              ## this buffer gets not filled completely
              ## anyway...
  # SIZE = 6291456
  STALLING_TIMEOUT = 250 # when full 
  # ENABLE_MONITORING = true # enables the throughput monitoring

import net, asyncdispatch, asyncnet, nativesockets
import types
import dbg
import tables
import strutils
import blacklistFancy # important, do not delete!!! : )
import nimSHA2
import reverseDomainNotation

# when ENABLE_MONITORING:
import byteCounter

type SocksServer = ref object
  listenPort: Port
  listenHost: string
  blacklistHost: seq[string]
  blacklistHostFancy: seq[BlacklistEntry]
  whitelistHost: seq[string]
  whitelistHostFancy: seq[BlacklistEntry]
  serverSocket: AsyncSocket
  staticHosts: Table[string, string]
  logFile: File
  logFileReverse: File
  users: TableRef[string, SHA512Digest]
  allowedAuthMethods: set[AuthenticationMethod]
  transferedBytes: int
  socks4Enabled: bool
  socks5Enabled: bool
  stallingTimeout: int
  byteCounter: ByteCounter

proc newSocksServer(
  listenPort: Port = Port(DEFAULT_PORT),
  listenHost: string = "",
  allowedAuthMethods: set[AuthenticationMethod] = {USERNAME_PASSWORD},
  socks4Enabled = false,
  socks5Enabled = true,
  stallingTimeout = STALLING_TIMEOUT

): SocksServer =
  result = SocksServer()
  result.listenPort = listenPort
  result.listenHost = listenHost
  result.blacklistHost = @[]
  result.blacklistHostFancy = @[]
  result.whitelistHost = @[]
  result.whitelistHostFancy = @[]
  result.serverSocket = newAsyncSocket()
  result.staticHosts = initTable[string, string]()
  result.logFile = open("hosts.txt", fmAppend)
  result.logFileReverse = open("hostsReverse.txt", fmAppend)
  result.users = newTable[string, SHA512Digest]()
  result.allowedAuthMethods = allowedAuthMethods
  result.transferedBytes = 0
  result.socks4Enabled = socks4Enabled
  result.socks5Enabled = socks5Enabled
  result.stallingTimeout = stallingTimeout
  result.byteCounter = newByteCounter()

proc isBlacklisted(proxy: SocksServer, host: string): bool =
  return host in proxy.blacklistHost or proxy.blacklistHostFancy.isListed(host)

proc isWhitelisted(proxy: SocksServer, host: string): bool =
  return host in proxy.whitelistHost or proxy.whitelistHostFancy.isListed(host)

proc isListed(proxy: SocksServer, host: string): bool = 
  if proxy.whitelistHost.len == 0 and proxy.whitelistHostFancy.len == 0:
    if proxy.isBlacklisted(host):
      dbg "Blacklisted host:", host
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
  if not proxy.users.hasKey(username): return false

  var
    hashedPassword = initSHA[SHA512]()
    hashFromDb = proxy.users[username]

  hashedPassword.update(username)
  hashedPassword.update(password)

  dbg "hashedPassword: ", hashedPassword
  dbg "hashFromDb: ", hashFromDb

  if hashedPassword.final() == hashFromDb:
    result = true

proc addUser(proxy: SocksServer, username: string, password: string) =
  if proxy.users.hasKey(username): raise newException(ValueError, "User already exists.")
  if username.len == 0: raise newException(ValueError, "Username required.")
  if password.len == 0: raise newException(ValueError, "Password required.")

  var hashedPassword = initSHA[SHA512]()
  hashedPassword.update(username)
  hashedPassword.update(password)

  proxy.users.add(username, hashedPassword.final())


proc pump(proxy: SocksServer, s1, s2: AsyncSocket, direction: Direction, ressource: seq[byte]): Future[void] {.async.} =
# TODO:
# from recv docs
# For buffered sockets this function will attempt to read all the requested data.
# It will read this data in BufferSize chunks.
# For unbuffered sockets this function makes no effort to read all the data requested.
# It will return as much data as the operating system gives it.
  var buffer = newStringOfCap( SIZE )
  while not (s1.isClosed() and s2.isClosed()):
    buffer.setLen 0
    try:
      ## Peek, so input buffer remains the same!
      buffer.add await s1.recv(SIZE, flags={SocketFlag.Peek, SocketFlag.SafeDisconn})
    except:
      buffer.setLen 0 

    if buffer.len > 0:
      try:
        discard await s1.recv(buffer.len) # TODO (better way?) we empty the buffer by reading it
      except:
        buffer.setLen 0
    else:
      try:
        buffer = await s1.recv(1) # we wait for new data...
      except:
        buffer.setLen 0

    if buffer.len == 0:
      # if one side closes we close both sides!
      break
    else:
      # write(stdout, buffer) ## DBG

      ## Throughtput monitoring

      proxy.byteCounter.count($ressource, direction, buffer.len)

      try:
        proxy.transferedBytes.inc(buffer.len)
      except:
        proxy.transferedBytes = 0 # reset if overflow

      try:
        await s2.send(buffer)
      except:
        dbg "send excepted"
        break

  if not s1.isClosed: s1.close()
  if not s2.isClosed: s2.close()

proc logHost(proxy: SocksServer, host: string) =
  proxy.logFile.writeLine(host)
  proxy.logFileReverse.writeLine(host.reverseNotation() )
  proxy.logFile.flushFile()
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
    host = socksReq.dst_addr.parseDestAddress(socksReq.atyp.ATYP)
    remoteSocket: AsyncSocket

  dbg "host: ", host
  dbg "--->: ", host.reverseNotation()
  host = proxy.getStaticRewrite(host)
  if proxy.isListed(host):
      var socksResp = newSocksResponse(socksReq, CONNECTION_NOT_ALLOWED_BY_RULESET)
      await client.send($socksResp)    
      return (false, nil)  
  proxy.logHost host
  var connectSuccess = true
  try:
    remoteSocket =  await asyncnet.dial(host, socksReq.dst_port.port())
    # should load data but not deliver to client (e.g. some anoying ads)
    # if host.contains("adition.com"):
    #   connectSuccess = false
  except:
    connectSuccess = false
  if not connectSuccess:
    var socksResp = newSocksResponse(socksReq, HOST_UNREACHABLE)
    await client.send($socksResp)
    echo "HOST_UNREACHABLE:", host
    return (false, nil)
  return (true, remoteSocket)

proc processSocks5(proxy: SocksServer, client: AsyncSocket): Future[void] {.async.} =
  # Handshake/Authentication
  var reqMessageSelection = RequestMessageSelection()
  if (await client.recvRequestMessageSelection(reqMessageSelection)) == false:
    dbg "could not parse RequestMessageSelection: ", reqMessageSelection.version
    client.close()
    return
  var respMessageSelection = ResponseMessageSelection()
  respMessageSelection.version = reqMessageSelection.version

  # Check if authentication method is supported and allowed by server
  if not (reqMessageSelection.methods in proxy.allowedAuthMethods):
    respMessageSelection.selectedMethod = NO_ACCEPTABLE_METHODS.byte
    await client.send($respMessageSelection)
    client.close()
    return

  # Chose authentication methods
  if USERNAME_PASSWORD.byte in reqMessageSelection.methods:
    dbg "Got user password Authentication"
    respMessageSelection.selectedMethod = USERNAME_PASSWORD.byte
    await client.send($respMessageSelection)
    
    var socksUserPasswordReq = SocksUserPasswordRequest()
    if (await client.recvSocksUserPasswordRequest(socksUserPasswordReq)) == false:
      client.close()
      return

    var socksUserPasswordResp = SocksUserPasswordResponse()
    socksUserPasswordResp.authVersion = AuthVersionV1.byte
    if proxy.authenticate($socksUserPasswordReq.uname, $socksUserPasswordReq.passwd):
      socksUserPasswordResp.status = UserPasswordStatus.SUCCEEDED.byte
      dbg "Sending good: ", repr($socksUserPasswordResp)
      await client.send($socksUserPasswordResp)
    else:
      socksUserPasswordResp.status = UserPasswordStatus.FAILED.byte
      dbg "Sending bad: ", repr($socksUserPasswordResp)
      await client.send($socksUserPasswordResp)
      client.close()
      return

  elif NO_AUTHENTICATION_REQUIRED.byte in reqMessageSelection.methods:
    respMessageSelection.selectedMethod = NO_AUTHENTICATION_REQUIRED.byte
    await client.send($respMessageSelection)
  else:
    dbg "Not supported authentication method"
    client.close()
    return

  # client sends what we should do
  var socksReq = SocksRequest()
  if (await client.recvSocksRequest(socksReq)) == false:
    dbg "Could not parse socksReq"
    client.close()
    return

  var
    remoteSocket: AsyncSocket = nil
    handleCmdSucceed: bool = false
  case socksReq.cmd.SocksCmd:
    of SocksCmd.CONNECT:
      (handleCmdSucceed, remoteSocket) = await proxy.handleSocks5Connect(client, socksReq)
    of SocksCmd.BIND:
      echo "BIND not implemented"
    of SocksCmd.UDP_ASSOCIATE:
      echo "UDP_ASSOCIATE not implemented"
    else:
      echo "not implemented"
      return

  if handleCmdSucceed == false:
    dbg "Handling command: failed"
    client.close()
    return
  dbg "Handling command: succeed"

  var
    socksResp = newSocksResponse(socksReq, SUCCEEDED)
    (hst, prt) = remoteSocket.getFd.getLocalAddr(Domain.AF_INET)
  socksResp.bnd_addr = @[hst.len.byte]
  socksResp.bnd_addr &= hst.toBytes()
  socksResp.bnd_port = prt.unPort
  await client.send($socksResp)

  asyncCheck proxy.pump(remoteSocket, client, downstream ,socksReq.dst_addr )
  asyncCheck proxy.pump(client, remoteSocket, upstream   ,socksReq.dst_addr )

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
    dbg host

  host = proxy.getStaticRewrite(host)
  if proxy.isListed(host):
      var socksResp = newSocks4Response(REQUEST_REJECTED_OR_FAILED)
      await client.send($socksResp)    
      return (false, nil)
  proxy.logHost (host)

  var connectSuccess = true
  try:
    remoteSocket =  await asyncnet.dial(host, socksReq.dst_port.port())
  except:
    connectSuccess = false

  if not connectSuccess:
    var socksResp = newSocks4Response(REQUEST_REJECTED_OR_FAILED)
    await client.send($socksResp)
    echo "HOST_UNREACHABLE:", host
    return (false, nil)

  return (true, remoteSocket)

proc processSocks4(proxy: SocksServer, client: AsyncSocket): Future[void] {.async.} =
  dbg "socks4"
  var socks4Request = Socks4Request()
  if (await client.recvSocks4Request(socks4Request)) == false:
    dbg "could not parse Socks4Request: " #, socks4Request
    client.close()
    return

  var
    remoteSocket: AsyncSocket = nil
    handleCmdSucceed: bool = false
  case socks4Request.cmd.Socks4Cmd
  of Socks4Cmd.CONNECT:
    # echo "CONNECT not implemented"
    (handleCmdSucceed, remoteSocket) = await proxy.handleSocks4Connect(client, socks4Request)
  of Socks4Cmd.BIND:
    echo "BIND not implemented"
  else:
    echo "not implemented"
    return

  if handleCmdSucceed == false:
    dbg "Handling command: failed"
    client.close()
    return
  dbg "Handling command: succeed"

  var
    socksResp = newSocks4Response(REQUEST_GRANTED)
  await client.send($socksResp)

  asyncCheck proxy.pump(remoteSocket, client, downstream , socks4Request.dst_ip )
  asyncCheck proxy.pump(client, remoteSocket, upstream   , socks4Request.dst_ip )

proc processClient(proxy: SocksServer, client: AsyncSocket): Future[void] {.async.} =
  # Check for socks version.
  var socksVersionRef = SocksVersionRef()
  if (await client.recvSocksVersion(socksVersionRef)) == false:
    dbg "unknown socks version: ", socksVersionRef.socksVersion
    client.close()
    return

  case socksVersionRef.socksVersion.SOCKS_VERSION
  of SOCKS_V4:
    if not proxy.socks4Enabled:
      client.close()
      return
    await proxy.processSocks4(client)
  of SOCKS_V5:
    if not proxy.socks5Enabled:
      client.close()
      return
    await proxy.processSocks5(client)

proc loadList(path: string): seq[string] =
  result = @[]
  var lineBuf = ""
  for line in lines path:
    lineBuf = line.strip()
    if lineBuf.startsWith('#'): continue
    result.add lineBuf

proc dumpThroughput(proxy: SocksServer): Future[void] {.async.} =
  ## TODO
  let tt = 10_000
  var last = 0
  shallowCopy last, proxy.transferedBytes.int
  while true:
    echo "throughput: ", formatSize(
      (proxy.transferedBytes - last)  div (tt div 1000),
      includeSpace = true
      ), "/s"
    shallowCopy last, proxy.transferedBytes.int
    ##
    # proxy.byteCounter.listRessources()
    proxy.byteCounter.dumpThroughput()
    ##
    await sleepAsync(tt)

proc serve(proxy: SocksServer): Future[void] {.async.} =
  proxy.serverSocket.setSockOpt(OptReuseAddr, true)
  proxy.serverSocket.bindAddr(proxy.listenPort, proxy.listenHost)
  proxy.serverSocket.listen()

  # TODO maybe do this:
  # if (not (NO_AUTHENTICATION_REQUIRED in proxy.allowedAuthMethods)) and (not proxy.socks5Enabled):
  #   raise newException(ValueError, "SOCKS4 does not support authentication, enable SOCKS5 ")
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
      echo getCurrentExceptionMsg()
      stalling = true
      continue

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
  var proxy = newSocksServer()
  proxy.socks4Enabled = true # no auth!
  proxy.allowedAuthMethods = {USERNAME_PASSWORD, NO_AUTHENTICATION_REQUIRED}
  proxy.addUser("hans", "peter")

  # proxy.blacklistHost = loadList("blacklist.txt")
  proxy.blacklistHostFancy = loadListFancy("blacklistFancy.txt")
  proxy.whitelistHostFancy = loadListFancy("whitelistFancy.txt")
  # proxy.whitelistHost = @[
  #   "example.org"
  # ]
  # proxy.staticHosts.add("foo.loc", "example.org")
  proxy.staticHosts.add("foo.loc", "example.org")
  asyncCheck proxy.serve()
  asyncCheck proxy.dumpThroughput()
  # asyncCheck proxy.dumpThroughput()
  runForever()
