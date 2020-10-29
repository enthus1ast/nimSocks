import serverTypes, asyncdispatch, dbg
from ressourceInfo import Ressource

proc pump*(proxy: SocksServer, s1, s2: AsyncSocket, direction: Direction, ressource: seq[byte], atyp: ATYP): Future[void] {.async.} =
  var buffer = newStringOfCap(SIZE)
  while not (s1.isClosed() and s2.isClosed()):
    buffer.setLen 0
    try:
      ## Peek, so input buffer remains the same!
      buffer.add await s1.recv(SIZE, flags={SocketFlag.Peek, SocketFlag.SafeDisconn})
    except:
      dbg 1, getCurrentExceptionMsg()
      buffer.setLen 0

    if buffer.len > 0:
      try:
        discard await s1.recv(buffer.len) # TODO (better way?) we empty the buffer by reading it
      except:
        dbg 2, getCurrentExceptionMsg()
        buffer.setLen 0
    else:
      try:
        buffer = await s1.recv(1) # we wait for new data...
      except:
        dbg 3, getCurrentExceptionMsg()
        buffer.setLen 0

    if buffer.len == 0:
      # if one side closes we close both sides!
      dbg "break 1"
      break
    else:
      ## Throughtput monitoring
      proxy.byteCounter.count(Ressource(kind: atyp, value: $ressource), direction, buffer.len)

      try:
        proxy.transferedBytes.inc(buffer.len)
      except:
        dbg 4, getCurrentExceptionMsg()
        proxy.transferedBytes = 0 # reset if overflow

      try:
        await s2.send(buffer)
      except:
        dbg 5, getCurrentExceptionMsg()
        dbg "send excepted"
        break

  if not s1.isClosed: s1.close()
  if not s2.isClosed: s2.close()
