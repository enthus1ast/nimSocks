import serverTypes, asyncdispatch, strutils
proc dumpThroughput*(proxy: SocksServer): Future[void] {.async.} =
  ## TODO
  let tt = 10_000
  var last = 0
  # shallowCopy last, proxy.transferedBytes.int
  while true:
    # echo "throughput: ", formatSize(
    #   (proxy.transferedBytes - last)  div (tt div 1000),
    #   includeSpace = true
    #   ), "/s"
    # shallowCopy last, proxy.transferedBytes.int
    # ##
    # proxy.byteCounter.listRessources()
    proxy.byteCounter.dumpThroughput()
    ##
    await sleepAsync(tt)