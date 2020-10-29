import serverTypes, asyncdispatch, dbg
from ressourceInfo import Ressource

proc pump*(proxy: SocksServer, s1, s2: AsyncSocket, direction: Direction, ressource: seq[byte], atyp: ATYP): Future[void] {.async.} =
  var buffer = newStringOfCap(SIZE)
  # var haveExbyte = false
  var exbyte: string # for avoiding sending 1 byte packages
  while not (s1.isClosed() and s2.isClosed()):
    buffer.setLen 0
    if exbyte.len > 0:
      # when we have an extra byte (from waiting),
      # we add it here to avoid sending 1 byte network packages
      buffer.add exbyte
    try:
      ## Peek, so input buffer remains the same!
      buffer.add await s1.recv(SIZE, flags={SocketFlag.Peek, SocketFlag.SafeDisconn})
    except:
      dbg 1, getCurrentExceptionMsg()
      buffer.setLen 0

    if buffer.len > 0:
      try:
        discard await s1.recv(buffer.len - exbyte.len) # TODO (better way?) we empty the buffer by reading it
        exbyte.setLen(0)
      except:
        dbg 2, getCurrentExceptionMsg()
        buffer.setLen 0
    else:
      try:
        exbyte = (await s1.recv(1)) # we wait for new data...
        if exbyte.len == 1:
          continue # the 1 byte get appended to the buffer in the next iteration
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
        # echo buffer.len
        await s2.send(buffer)
      except:
        dbg 5, getCurrentExceptionMsg()
        dbg "send excepted"
        break

  if not s1.isClosed: s1.close()
  if not s2.isClosed: s2.close()
