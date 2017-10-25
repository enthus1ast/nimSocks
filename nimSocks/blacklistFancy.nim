import strutils

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

when isMainModule:
  assert parseBlacklistLine("sta foo") == (STA, "foo" )
  assert parseBlacklistLine("sta  foo")  == (STA, "foo" )
  assert parseBlacklistLine("end porn.com").matched("geiletitten.mira.porn.com") == true
  # assert parseBlacklistLine("# sta  foo")  == (REM, "sta  foo")

  var blackList = loadListFancy("blacklistFancy.txt")
  for bentry in blackList:
    echo $bentry, " | LISTED => ", bentry.matched("geiletitten.mira.porn.com")
