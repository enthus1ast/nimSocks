## test simple domain filters


import ../../nimSocks/domainfilter, os


# tests the simple filter language
doAssert parseBlacklistLine("sta foo") == (STA, "foo" )
doAssert parseBlacklistLine("sta  foo")  == (STA, "foo")

doAssert parseBlacklistLine("end facebook.com").matched("www2.facebook.com") == true

doAssert parseBlacklistLine("con ads").matched("ads.example.org") == true
doAssert parseBlacklistLine("con ads").matched("some.ads.example.org") == true

doAssert parseBlacklistLine("eql example.org").matched("example.org") == true

doAssert loadListFromStr("#eql some stuff\neql example.org")[0].matched("example.org") == true
doAssert loadListFromStr("\neql example.org")[0].matched("example.org") == true


let exampleFancyFilter = """
# Some comment
## more comments
eql example.org
sta ads
end hyper.org
con foo
"""
let ffilter = loadListFromStr(exampleFancyFilter)
doAssert ffilter.isListed("example.org") == true
doAssert ffilter.isListed("ads.fasdf.org") == true
doAssert ffilter.isListed("hyper.org") == true
doAssert ffilter.isListed("foo.baa") == true

doAssert ffilter.isListed("example.org.net") == false
doAssert ffilter.isListed("www.ads.fasdf.org") == false
doAssert ffilter.isListed("hyper.org.test") == false
doAssert ffilter.isListed("f00.baa") == false
doAssert ffilter.isListed("FOO.baa") == false


let exampleSimpleFilter = """
foo
baa
baz
"""
let path = getTempDir() / "tDomainFilterSimpleBlacklist.txt"
writeFile(path, exampleSimpleFilter)
let filterFromFile = loadList(path)
doAssert filterFromFile.isListed("foo") == true
doAssert filterFromFile.isListed("baa") == true
doAssert filterFromFile.isListed("baz") == true
removeFile(path)

let filterFromMem = useList(exampleSimpleFilter)
doAssert filterFromMem.isListed("foo") == true
doAssert filterFromMem.isListed("baa") == true
doAssert filterFromMem.isListed("baz") == true

