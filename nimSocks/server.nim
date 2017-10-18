import net, asyncdispatch, asyncnet, nativesockets
import types
import dbg
import tables
import strutils
import blacklistFancy # important, do not delete!!! : )
import nimSHA2

const
  SIZE = 1024 ## max size the buffer could be
              ## but since we peek on the sockets,
              ## this buffer gets not filled completely
              ## anyway...

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
  users: TableRef[string, SHA512Digest]
  allowedAuthMethods: set[AuthenticationMethod]
  transferedBytes: int 
  socks4Enabled: bool
  socks5Enabled: bool

proc newSocksServer(
  listenPort: Port = Port(DEFAULT_PORT),
  listenHost: string = "",
  allowedAuthMethods: set[AuthenticationMethod] = {USERNAME_PASSWORD},
  socks4Enabled = false, 
  socks5Enabled = true

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
  result.logFile = open("hosts.txt", fmWrite)
  result.users = newTable[string, SHA512Digest]()
  result.allowedAuthMethods = allowedAuthMethods
  result.transferedBytes = 0
  result.socks4Enabled = socks4Enabled
  result.socks5Enabled = socks5Enabled

proc isBlacklisted(proxy: SocksServer, host: string): bool =
  return host in proxy.blacklistHost or proxy.blacklistHostFancy.isListed(host)

proc isWhitelisted(proxy: SocksServer, host: string): bool =
  return host in proxy.whitelistHost or proxy.whitelistHostFancy.isListed(host)

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


proc pump(proxy: SocksServer, s1, s2: AsyncSocket): Future[void] {.async.} =

# TODO:
# from recv docs
# For buffered sockets this function will attempt to read all the requested data. 
# It will read this data in BufferSize chunks.
# For unbuffered sockets this function makes no effort to read all the data requested. 
# It will return as much data as the operating system gives it.

  while not (s1.isClosed() and s2.isClosed() ):
    var buffer: string
    try:
      ## Peek, so input buffer remains the same!
      # buffer = await src.recv(SIZE, timeout=2,flags={SocketFlag.Peek, SocketFlag.SafeDisconn})
      buffer = await s1.recv(SIZE, flags={SocketFlag.Peek, SocketFlag.SafeDisconn})
    except:
      buffer = ""

    if buffer.len > 0:
      try:
        discard await s1.recv(buffer.len) # TODO (better way?) we empty the buffer by reading it 
      except:
        buffer = ""
    else:
      try:
        buffer = await s1.recv(1) # we wait for new data...
      except:
        buffer = ""        

    if buffer == "":
      # if one side closes we close both sides!
      # s1.close()
      # s2.close()    
      break
    else:
      # write(stdout, buffer)

      ## Throughtput moitoring
      try:
        proxy.transferedBytes.inc(buffer.len)
      except:
        proxy.transferedBytes = 0 # reset if overflow

      await s2.send(buffer)
    
  if not s1.isClosed: s1.close()
  if not s2.isClosed: s2.close()


proc handleSocks5Connect(
  proxy: SocksServer,
  client: AsyncSocket,
  socksReq: SocksRequest
): Future[(bool, AsyncSocket)] {.async.} =
  var
    host = socksReq.dst_addr.parseDestAddress(socksReq.atyp.ATYP)
    remoteSocket: AsyncSocket

  dbg "host: ", host
  if proxy.staticHosts.contains host:
    host = proxy.staticHosts[host]
  elif proxy.whitelistHost.len == 0 and proxy.whitelistHostFancy.len == 0:
    if proxy.isBlacklisted(host):
      var socksResp = newSocksResponse(socksReq, CONNECTION_NOT_ALLOWED_BY_RULESET)
      await client.send($socksResp)
      echo "Blacklisted host:", host
      return (false, nil)
  else:
    if not proxy.isWhitelisted(host):
      var socksResp = newSocksResponse(socksReq, CONNECTION_NOT_ALLOWED_BY_RULESET)
      await client.send($socksResp)
      echo "Not whitelisted host:", host
      return (false, nil)

  proxy.logFile.writeLine(host)
  proxy.logFile.flushFile()

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
    (hst, prt) = remoteSocket.getFd.getLocalAddr(AF_INET)
  socksResp.bnd_addr = @[hst.len.byte]
  socksResp.bnd_addr &= hst.toBytes()
  socksResp.bnd_port = prt.unPort
  await client.send($socksResp)

  asyncCheck proxy.pump(remoteSocket, client)
  asyncCheck proxy.pump(client, remoteSocket)


proc isSocks4aHack(dst_ip: seq[byte]): bool =
  return 
    dst_ip[0] == NULL and 
    dst_ip[1] == NULL and
    dst_ip[2] == NULL and
    dst_ip[3] != NULL

proc handleSocks4Connect(
  proxy: SocksServer,
  client: AsyncSocket,
  socksReq: Socks4Request
): Future[(bool, AsyncSocket)] {.async.} =
  var
    host = socksReq.dst_ip.parseDestAddress(IP_V4_ADDRESS)
    remoteSocket: AsyncSocket
    
  dbg "host: ", host
  if socksReq.dst_ip.isSocks4aHack():
    dbg "socks4a"
    # host = socksReq.userid.parseDestAddress(DOMAINNAME)
    host = (await client.recvNullTerminated()).parseDestAddress(DOMAINNAME)
    dbg host

  if proxy.staticHosts.contains host:
    host = proxy.staticHosts[host]
  elif proxy.whitelistHost.len == 0 and proxy.whitelistHostFancy.len == 0:
    if proxy.isBlacklisted(host):
      var socksResp = newSocks4Response(REQUEST_REJECTED_OR_FAILED, socksReq.dst_ip, socksReq.dst_port)
      await client.send($socksResp)
      echo "Blacklisted host:", host
      return (false, nil)
  else:
    if not proxy.isWhitelisted(host):
      var socksResp = newSocks4Response(REQUEST_REJECTED_OR_FAILED, socksReq.dst_ip, socksReq.dst_port)
      await client.send($socksResp)
      echo "Not whitelisted host:", host
      return (false, nil)

  proxy.logFile.writeLine(host)
  proxy.logFile.flushFile()

  var connectSuccess = true
  try:
    remoteSocket =  await asyncnet.dial(host, socksReq.dst_port.port())
  except:
    connectSuccess = false

  if not connectSuccess:
    var socksResp = newSocks4Response(REQUEST_REJECTED_OR_FAILED, socksReq.dst_ip, socksReq.dst_port)
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
    socksResp = newSocks4Response(REQUEST_GRANTED, socks4Request.dst_ip, socks4Request.dst_port)
    (hst, prt) = remoteSocket.getFd.getLocalAddr(AF_INET)
  # socksResp.dst_ip = @[hst.len.byte]
  socksResp.dst_ip = @[1.byte,2.byte,4.byte,4.byte] #hst.toBytes().parseDestAddress(IP_V4_ADDRESS).toBytes()
  socksResp.dst_port = prt.unPort
  echo repr socksResp
  await client.send($socksResp)

  asyncCheck proxy.pump(remoteSocket, client)
  asyncCheck proxy.pump(client, remoteSocket)
  # discard

proc processClient(proxy: SocksServer, client: AsyncSocket): Future[void] {.async.} =

  # Check for socks version.
  var socksVersionRef = SocksVersionRef()
  if (await client.recvSocksVersion(socksVersionRef)) == false:
    dbg "unknown socks version: ", socksVersionRef.socksVersion
    client.close()
    return

  case socksVersionRef.socksVersion.SOCKS_VERSION
  of SOCKS_V4:
    await proxy.processSocks4(client)
  of SOCKS_V5:
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
    echo "throughput: ", ( (proxy.transferedBytes - last) / 1024 ) / (tt / 1000) , " kb/s" 
    shallowCopy last, proxy.transferedBytes.int
    await sleepAsync(tt)

proc serve(proxy: SocksServer): Future[void] {.async.} =
  proxy.serverSocket.setSockOpt(OptReuseAddr, true)
  proxy.serverSocket.bindAddr(proxy.listenPort, proxy.listenHost)
  proxy.serverSocket.listen()

  # TODO maybe do this:
  # if (not (NO_AUTHENTICATION_REQUIRED in proxy.allowedAuthMethods)) and (not proxy.socks5Enabled):
  #   raise newException(ValueError, "SOCKS4 does not support authentication, enable SOCKS5 ")
  
  while true:
    let (address, client) = await proxy.serverSocket.acceptAddr()
    client.setSockOpt(OptReuseAddr, true)
    echo "connection from: ", address
    asyncCheck proxy.processClient(client)


when isMainModule:
  var proxy = newSocksServer()
  proxy.socks4Enabled = true # no auth!
  proxy.allowedAuthMethods = {USERNAME_PASSWORD, NO_AUTHENTICATION_REQUIRED}
  proxy.addUser("hans", "peter")

  block:
    assert proxy.authenticate("hans", "peter") == true
    assert proxy.authenticate(" hans", "peter") == false
    assert proxy.authenticate("hans", "peter ") == false
    assert proxy.authenticate(" hans", "peter ") == false
    assert proxy.authenticate("as hans", "dd cpeter ") == false

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
  runForever()
