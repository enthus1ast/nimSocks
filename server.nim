import net, asyncdispatch, asyncnet, nativesockets
import types
import dbg
import tables
import strutils
import blacklistFancy # important, do not delete!!! : )

const
  SIZE = 1024 ## max size the buffer could be
              ## but since we peek on the sockets,
              ## this buffer gets not filled completely
              ## anyway...

type SocksServer = object 
  listenPort: Port
  listenHost: string
  blacklistHost: seq[string]
  blacklistHostFancy: seq[BlacklistEntry]
  whitelistHost: seq[string]
  serverSocket: AsyncSocket
  staticHosts: Table[string, string]
  logFile: File

proc newSocksServer(listenPort: Port = Port(DEFAULT_PORT), listenHost: string = ""): SocksServer =
  result = SocksServer()
  result.listenPort = listenPort
  result.listenHost = listenHost
  result.blacklistHost = @[]
  result.blacklistHostFancy = @[]
  result.whitelistHost = @[]
  result.serverSocket = newAsyncSocket()
  result.staticHosts = initTable[string, string]()
  result.logFile = open("hosts.txt", fmWrite)

proc toSeq(str: string): seq[byte] = 
  result = @[]
  for ch in str:
    result.add ch.byte

proc `$`(rms: ResponseMessageSelection): string =
  result = ""
  result.add rms.version.char
  result.add rms.selectedMethod.char

proc `$`(sr: SocksResponse): string =
  result = ""
  result.add sr.version.char
  result.add sr.rep.char
  result.add sr.rsv.char
  result.add sr.atyp.char
  # if sr.atyp.ATYP == DOMAINNAME:
  #   result.add sr.bnd_addr.len.char
  result.add $sr.bnd_addr
  result.add sr.bnd_port.h.char
  result.add sr.bnd_port.l.char

proc parseDestAddress(bytes: seq[byte], atyp: ATYP): string =
  result = ""
  for idx, ch in bytes:
    case atyp
    of DOMAINNAME:
      result.add(ch.chr())
    of IP_V4_ADDRESS: 
      result.add($ch)
      if idx != 3: result.add('.')
    of IP_V6_ADDRESS:
      result.add($ch)
      if idx != 15: result.add(':')

proc port(t: tuple[h, l: byte]): Port =
  return Port(t.h.int * 256 + t.l.int)

proc unPort(p: Port): tuple[h, l: byte] =
  return ((p.int div 256).byte, (p.int mod 256).byte) 

proc recvByte(client: AsyncSocket): Future[byte] {.async.} =
  return (await client.recv(1))[0].byte

proc recvBytes(client: AsyncSocket, count: int): Future[seq[byte]] {.async.} =
  return (await client.recv(count)).toSeq()

proc toBytes(str: string): seq[byte] =
  result = @[]
  for ch in str:
    result.add ch.byte

proc recvCString(client: AsyncSocket): Future[seq[byte]] {.async.} =
  result = @[]
  var ch: byte
  while true:
    ch = await client.recvByte
    if ch == 0x00.byte: break
    result.add(ch.byte)

proc pump(s1, s2: AsyncSocket): Future[void] {.async.} =
  # var buf = ""
  # while true:
  #   buf = await s1.recv(1)
  #   # echo buf
  #   if buf == "": break
  #   await s2.send(buf)
  #   buf.setLen 0

  while true:
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
      await s2.send(buffer)

proc isBlacklisted(proxy: SocksServer, host: string): bool =
  return host in proxy.blacklistHost or proxy.blacklistHostFancy.isListed(host)

proc isWhitelisted(proxy: SocksServer, host: string): bool =
  return host in proxy.whitelistHost

proc processClient(proxy: SocksServer, client: AsyncSocket): Future[void] {.async.} =
  # Handshake/Authentication

  var reqMessageSelection = RequestMessageSelection()

  reqMessageSelection.version = await client.recvByte
  if reqMessageSelection.version != SOCKS_V5: 
    dbg "not supported version: ", reqMessageSelection.version
    client.close()
    return

  reqMessageSelection.methodsLen = await client.recvByte
  if reqMessageSelection.methodsLen < 1: 
    dbg "err: ", reqMessageSelection.methodsLen
    client.close()
    return

  var respMessageSelection = ResponseMessageSelection()
  respMessageSelection.version = SOCKS_V5

  reqMessageSelection.methods = await client.recvBytes(reqMessageSelection.methodsLen.int)
  dbg reqMessageSelection
  if not NO_AUTHENTICATION_REQUIRED.byte in reqMessageSelection.methods: 
    respMessageSelection.selectedMethod = NO_ACCEPTABLE_METHODS.byte
    await client.send($respMessageSelection)
    client.close()
    return

  respMessageSelection.selectedMethod = NO_AUTHENTICATION_REQUIRED.byte
  await client.send($respMessageSelection)

  # client sends what we should do
  var socksReq = SocksRequest()
  socksReq.version = await client.recvByte # *: byte
  socksReq.cmd = await client.recvByte # *: byte
  socksReq.rsv = await client.recvByte # *: byte
  socksReq.atyp = await client.recvByte # *: byte
  socksReq.dst_addr = case socksReq.atyp.ATYP
    of IP_V4_ADDRESS: await client.recvBytes(4)
    of DOMAINNAME: await client.recvBytes((await client.recvByte).int)
    of IP_V6_ADDRESS: await client.recvBytes(16)
  socksReq.dst_port = (await client.recvByte, await client.recvByte) # *: tuple[h: byte, l: byte]
  # dbg "Dest Data: ", socksReq
  # dbg "Port: ", socksReq.dst_port.port()

  var remoteSocket: AsyncSocket
  case socksReq.cmd.SocksCmd:
    of CONNECT:
      var host = socksReq.dst_addr.parseDestAddress(socksReq.atyp.ATYP)
      dbg "host: ", host

      if proxy.staticHosts.contains host:
        host = proxy.staticHosts[host]
      elif proxy.whitelistHost.len == 0:
        if proxy.isBlacklisted(host):
          var socksResp = newSocksResponse(socksReq, CONNECTION_NOT_ALLOWED_BY_RULESET)
          await client.send($socksResp)
          echo "Blacklisted host:", host
          return
      else:
        if not proxy.isWhitelisted(host):
          var socksResp = newSocksResponse(socksReq, CONNECTION_NOT_ALLOWED_BY_RULESET)
          await client.send($socksResp)
          echo "Not whitelisted host:", host
          return

      proxy.logFile.writeLine(host)
      proxy.logFile.flushFile()

      var connectSuccess = true
      try:
        remoteSocket =  await asyncnet.dial(host, socksReq.dst_port.port())
        # if host.contains("adition.com"):
        #   connectSuccess = false
      except:
        connectSuccess = false

      if not connectSuccess:
        var socksResp = newSocksResponse(socksReq, HOST_UNREACHABLE)
        await client.send($socksResp)
        echo "HOST_UNREACHABLE:", host        
        return



    of BIND:
      echo "not implemented"
    of UDP_ASSOCIATE:
      echo "not implemented"
    else:
      echo "not implemented"
      return

  # if socksResp.atyp.ATYP == DOMAINNAME:
  #   socksResp.bnd_addr = @[]
  #   socksResp.bnd_addr.add socksReq.dst_addr.len.byte
  #   socksResp.bnd_addr &= socksReq.dst_addr
  # else:
  #   socksResp.bnd_addr = socksReq.dst_addr
  var
    socksResp = newSocksResponse(socksReq, SUCCEEDED)
    (hst, prt) = remoteSocket.getFd.getLocalAddr(AF_INET)
  socksResp.bnd_addr = @[hst.len.byte]
  socksResp.bnd_addr &= hst.toBytes
  socksResp.bnd_port = prt.unPort
  echo repr socksResp
  await client.send($socksResp)


  asyncCheck pump(remoteSocket, client)
  asyncCheck pump(client, remoteSocket)
  # After client is authenticated:
  # while true:
  #   echo $(await remoteSocket.recvByte)
    # if line.len == 0: break
    # for c in clients:
    #   await c.send(line & "\c\L")

proc loadList(path: string): seq[string] =
  result = @[]
  var lineBuf = ""
  for line in lines path:
    lineBuf = line.strip()
    if lineBuf.startsWith('#'): continue
    result.add lineBuf

proc serve(proxy: SocksServer): Future[void] {.async.} =
  # proxy.serverSocket = newAsyncSocket()
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
  # proxy.blacklistHost = loadList("blacklist.txt")
  proxy.blacklistHostFancy = loadFile("blacklistFancy.txt")
  # proxy.whitelistHost = @[
  #   "ch4t.code0.xyz"
  # ]
  # proxy.staticHosts.add("foo.loc", "ch4t.code0.xyz")
  proxy.staticHosts.add("foo.loc", "93.197.78.252")
  asyncCheck proxy.serve()
  runForever()
