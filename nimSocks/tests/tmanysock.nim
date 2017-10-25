import asyncnet, asyncdispatch

proc m(): Future[void] {.async.} =
  var socks = newSeq[AsyncSocket]()
  for idx in 0..10_000:
    socks.add await asyncnet.dial("127.0.0.1", Port 1080)
    echo idx
  discard readLine(stdin)

waitFor m()