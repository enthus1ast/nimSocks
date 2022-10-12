import chronos
import std/sequtils
import chronos/transports/stream
export chronos, stream

type AsyncSocket* = StreamTransport

proc send*(t: AsyncSocket, data: string) {.async.} =
  discard await t.write(data)

proc toSeq*(s: seq[byte]): seq[byte] = s

proc recv*(t: AsyncSocket, count: int): Future[seq[byte]] {.async.} =
  var res = newSeq[byte](count)
  await t.readExactly(res[0].addr, count)
  return res
