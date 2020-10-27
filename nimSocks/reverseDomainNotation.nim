#
#
#                  nimSocks
#          SOCKS4/4a/5 proxy server
#            (c) Copyright 2020
#        David Krause, Tobias Freitag
#
#    See the file "LICENSE", included in this
#    distribution, for details about the copyright.
#

proc reverseNotation*(hostname: string): string =
  ## returns the reverse domain notation of the given hostname
  ##  https://en.wikipedia.org/wiki/Reverse_domain_name_notation
  ## A high performance version of this:
  ##   return hostname.split(".").reversed().join(".")
  result = ""
  var
    pos: int = 0
    buf: string = ""
    ch: char
  while true:
    if pos == hostname.len:
      result.insert(buf,0)
      break
    ch = hostname[pos]
    if ch == '.':
        buf.insert $ch, 0
        result.insert(buf,0)
        buf.setLen 0
    else:
        buf.add ch
    pos.inc

when isMainModule:
  ## Naive module for performance-testing
  import dbg
  import strutils
  import algorithm
  proc reverseDomain(domain: string): string =
    return domain.split(".").reversed().join(".")

  timeIt "fast":
    discard reverseNotation("foo.baa.foo.baa.foo.baa")

  timeIt "slow":
    discard reverseDomain("foo.baa.foo.baa.foo.baa")

when isMainModule:
    assert  "foo".reverseNotation == "foo"
    assert  "foo.baa".reverseNotation == "baa.foo"
    assert  "foo.baa.baz".reverseNotation == "baz.baa.foo"
    assert  "".reverseNotation == ""
    assert  ".".reverseNotation == "."
    assert  "..".reverseNotation == ".."
    assert "foo.baa".reverseNotation.reverseNotation == "foo.baa"
    assert "server.example.loc".reverseNotation() == "server.example.loc".reverseDomain()