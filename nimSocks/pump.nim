import serverTypes, asyncdispatch, dbg

proc pump*(proxy: SocksServer, s1, s2: AsyncSocket, direction: Direction, ressource: seq[byte]): Future[void] {.async.} =
  # TODO:
  # from recv docs
  # For buffered sockets this function will attempt to read all the requested data.
  # It will read this data in BufferSize chunks.
  # For unbuffered sockets this function makes no effort to read all the data requested.
  # It will return as much data as the operating system gives it.
  var buffer = newStringOfCap(SIZE)
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
