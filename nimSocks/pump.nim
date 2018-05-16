import serverTypes, asyncdispatch, dbg

proc pump*(proxy: SocksServer, s1, s2: AsyncSocket, direction: Direction, ressource: seq[byte]): Future[void] {.async.} =
  var buffer = newStringOfCap(SIZE)
  while not (s1.isClosed() and s2.isClosed()):
    dbg "in pump"
    buffer.setLen 0
    try:
      ## Peek, so input buffer remains the same!
      buffer.add await s1.recv(SIZE, flags={SocketFlag.Peek, SocketFlag.SafeDisconn})
    except:
      echo 1, getCurrentExceptionMsg()
      buffer.setLen 0 

    if buffer.len > 0:
      try:
        discard await s1.recv(buffer.len) # TODO (better way?) we empty the buffer by reading it
      except:
        echo 2, getCurrentExceptionMsg()
        buffer.setLen 0
    else:
      try:
        buffer = await s1.recv(1) # we wait for new data...
      except:
        echo 3, getCurrentExceptionMsg()
        buffer.setLen 0

    if buffer.len == 0:
      # if one side closes we close both sides!
      echo "break 1"
      break
    else:
      # write(stdout, buffer) ## DBG
      ## Throughtput monitoring
      proxy.byteCounter.count($ressource, direction, buffer.len)

      try:
        proxy.transferedBytes.inc(buffer.len)
      except:
        echo 4, getCurrentExceptionMsg()
        proxy.transferedBytes = 0 # reset if overflow

      try:
        await s2.send(buffer)
      except:
        echo 5, getCurrentExceptionMsg()
        dbg "send excepted"
        break

  if not s1.isClosed: s1.close()
  if not s2.isClosed: s2.close()
