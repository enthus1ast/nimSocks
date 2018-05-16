#
#
#                  nimSocks
#          SOCKS4/4a/5 proxy server
#            (c) Copyright 2018
#        David Krause, Tobias Freitag
#
#    See the file "LICENSE", included in this
#    distribution, for details about the copyright.

import tables, strutils

type 
  Direction* = enum
    upstream, downstream
  Ressource* = string
  RessourceInfo* = tuple[up, down: int]
  ByteCounter* = ref object
    globalUpBytes*: int   # to the remote server
    globalDownBytes*: int # from the remote server TO the client
    ressourceTable: CountTable[(Ressource, Direction)]
    ressourceTableThrougput: CountTable[(Ressource, Direction)]

proc newByteCounter*(): ByteCounter =
  result = ByteCounter()
  result.globalDownBytes = 0
  result.globalUpBytes = 0
  result.ressourceTable = initCountTable[(Ressource, Direction)]()
  result.ressourceTableThrougput = initCountTable[(Ressource, Direction)]()

proc count*(byteCounter: ByteCounter, ressource: Ressource, direction: Direction, cnt: int = 1) = 
  case direction
  of upstream:
    byteCounter.globalUpBytes.inc cnt
  of downstream:
    byteCounter.globalDownBytes.inc cnt
  byteCounter.ressourceTable.inc( (ressource,direction), cnt )
  byteCounter.ressourceTableThrougput.inc( (ressource,direction), cnt )

proc globalTransferedBytes*(byteCounter: ByteCounter): int =
  return byteCounter.globalDownBytes + byteCounter.globalUpBytes

proc `$`*(byteCounter: ByteCounter): string =
  result = ""
  result.add "#".repeat(30) & "\p"
  result.add "globalUpBytes: " & $byteCounter.globalUpBytes & "\p"
  result.add "globalDownBytes: " & $byteCounter.globalDownBytes & "\p"
  result.add "globalTransferedBytes: " & $byteCounter.globalTransferedBytes() & "\p"
  # result.add "globalUpBytes: ", byteCounter.globalUpBytes , "\p"
  # result.add "globalUpBytes: ", byteCounter.globalUpBytes , "\p"
  result.add "^".repeat(30) & "\p"

proc ressourceInfo*(byteCounter: ByteCounter, ressource: string): RessourceInfo =
  result.up = byteCounter.ressourceTable[(ressource, upstream)]
  result.down =  byteCounter.ressourceTable[(ressource, downstream)]  

proc listRessources*(byteCounter: ByteCounter) =
  for each in byteCounter.ressourceTable.pairs():
    echo each

proc dumpThroughput*(byteCounter: ByteCounter, perSeconds = 10) =
  var str: string = ""

  str.add "Througput ( " & $perSeconds & " seconds ):\p"
  for k, v in byteCounter.ressourceTableThrougput.pairs():
    # case k[1]
    # of upstream:
    #   str.add " <== "
    # of downstream:
    #   str.add " ==> "
    str.add "$#\t$#/s \t$# \p" % [($k[1]).align(10), (v.div perSeconds).formatSize.align(8), $k[0]]#   "\t -", k[0], " =" , k[1] , "=> " , v.formatSize
  echo str
  byteCounter.ressourceTableThrougput.clear()

when isMainModule:
  var bc = newByteCounter()
  bc.count( "klaus", upstream )
  bc.count( "klaus", upstream )
  bc.count( "klaus", upstream )
  bc.count( "klaus", upstream )
  bc.count( "klaus", downstream )
  # echo bc.ressourceTable[("klaus", upstream)]
  # echo bc.ressourceTable[("klaus", downstream)]
  echo "klaus: ", bc.ressourceInfo("klaus")
  echo $bc
  bc.listRessources()
