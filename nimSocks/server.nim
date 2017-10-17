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

proc newSocksServer(
  listenPort: Port = Port(DEFAULT_PORT),
  listenHost: string = "",
  allowedAuthMethods: set[AuthenticationMethod] = {USERNAME_PASSWORD}
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

proc processClient(proxy: SocksServer, client: AsyncSocket): Future[void] {.async.} =
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
    socksUserPasswordResp.authVersion = 0x01
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
    of CONNECT:
      (handleCmdSucceed, remoteSocket) = await proxy.handleSocks5Connect(client, socksReq)
    of BIND:
      echo "not implemented"
    of UDP_ASSOCIATE:
      echo "not implemented"
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

proc loadList(path: string): seq[string] =
  result = @[]
  var lineBuf = ""
  for line in lines path:
    lineBuf = line.strip()
    if lineBuf.startsWith('#'): continue
    result.add lineBuf

proc dumpThroughtput(proxy: SocksServer): Future[void] {.async.} =
  let tt = 10_000
  var last = 0
  shallowCopy last, proxy.transferedBytes.int
  while true:
    echo "Throughtput: ", ( (proxy.transferedBytes - last) / 1024 ) / (tt / 1000) , " kb/s" 
    shallowCopy last, proxy.transferedBytes.int
    await sleepAsync(tt)

proc serve(proxy: SocksServer): Future[void] {.async.} =
  proxy.serverSocket.setSockOpt(OptReuseAddr, true)
  proxy.serverSocket.bindAddr(proxy.listenPort, proxy.listenHost)
  proxy.serverSocket.listen()
  
  while true:
    let (address, client) = await proxy.serverSocket.acceptAddr()
    client.setSockOpt(OptReuseAddr, true)
    echo "connection from: ", address
    asyncCheck proxy.processClient(client)


when isMainModule:
  var proxy = newSocksServer()
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
  #   "ch4t.code0.xyz",
  #   "pr0gramm.com",
  #   "api.pr0gramm.com",
  #   "thumb.pr0gramm.com"
  # ]
  # proxy.staticHosts.add("foo.loc", "ch4t.code0.xyz")
  proxy.staticHosts.add("foo.loc", "ch4t.code0.xyz")
  asyncCheck proxy.serve()
  asyncCheck proxy.dumpThroughtput()
  runForever()
