#
#
#                  nimSocks
#          SOCKS4/4a/5 proxy server
#            (c) Copyright 2018
#        David Krause, Tobias Freitag
#
#    See the file "LICENSE", included in this
#    distribution, for details about the copyright.
#
## nimSocks small filter language.

import strutils, sets, hashes, dbg

type
  CheckType* = enum
    STA = "sta" # match start
    END = "end" # match end
    CON = "con" # contains
    EQL = "eql" # equal
  BlacklistEntry* = tuple
    checkType: CheckType
    line: string

proc parseBlacklistLine*(str: string): BlacklistEntry =
  return (parseEnum[CheckType](str.strip()[0..2]), str.strip()[3..^1].strip())

proc matched*(bentry: BlacklistEntry, str: string): bool =
  return case bentry.checkType
  of STA: str.startsWith(bentry.line)
  of END: str.endsWith(bentry.line)
  of CON: str.contains(bentry.line)
  of EQL: str == bentry.line

proc loadListFromStr*(str: string): seq[BlacklistEntry] =
  result = @[]
  var idx = 0
  for ln in str.splitLines():
    idx.inc
    if ln.strip().len == 0: continue
    if ln.strip().startsWith('#'): continue
    let be = parseBlacklistLine(ln)
    if be.line == "":
      dbg "Empty rule on line:", idx
    else:
      result.add be

proc loadListFancy*(path: string): seq[BlacklistEntry] =
  return loadListFromStr(readFile(path))

proc isListed*(bentries: seq[BlacklistEntry], host: string): bool {.inline.} =
  ## Returns true if the given host ist listed in Fancy filters list
  for bentry in bentries:
    if bentry.matched(host) == true: return true
  return false

proc isListed*(bentries: HashSet[Hash], host: string): bool {.inline.} =
  ## Returns true if the given host ist listed in simple filters list
  return hash(host) in bentries

template sanLine(ll: HashSet[Hash], line: string) =
  let lineBuf = line.strip()
  if not lineBuf.startsWith('#'):
    ll.incl hash(lineBuf)

proc useList*(str: string): HashSet[Hash] =
  ## loads a simple filter list from memory
  ## simple filters are faster then fancy filters!
  result = initHashSet[Hash]()
  for line in str.splitLines():
    result.sanLine(line)

proc loadList*(path: string): HashSet[Hash] =
  ## loads a simple filter list from filesystem
  ## simple filters are faster then fancy filters!
  result = initHashSet[Hash]()
  for line in lines path:
    result.sanLine(line)