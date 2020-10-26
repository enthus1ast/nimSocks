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

import strutils, sets, hashes

type
  CheckType* = enum
    # REM = "#"
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
      echo "Empty rule on line:", idx
    else:
      result.add be

proc loadListFancy*(path: string): seq[BlacklistEntry] =
  return loadListFromStr(readFile(path))

proc isListed*(bentries: seq[BlacklistEntry], host: string): bool =
  for bentry in bentries:
    if bentry.matched(host) == true: return true
  return false


# The 'legacy' filter functions
proc loadList*(path: string): HashSet[Hash]=
  result = initHashSet[Hash]()
  var lineBuf = ""
  for line in lines path:
    lineBuf = line.strip()
    if lineBuf.startsWith('#'): continue
    result.incl hash(lineBuf)


when isMainModule:
  assert parseBlacklistLine("sta foo") == (STA, "foo" )
  assert parseBlacklistLine("sta  foo")  == (STA, "foo" )
  assert parseBlacklistLine("end facebook.com").matched("www2.facebook.com") == true
  # assert parseBlacklistLine("# sta  foo")  == (REM, "sta  foo")

  var blackList = loadListFancy("blacklistFancy.txt")
  for bentry in blackList:
    echo $bentry, " | LISTED => ", bentry.matched("www2.facebook.com")

