## test simple domain filters


import ../../nimSocks/domainfilter

doAssert parseBlacklistLine("sta foo") == (STA, "foo" )
doAssert parseBlacklistLine("sta  foo")  == (STA, "foo")

doAssert parseBlacklistLine("end facebook.com").matched("www2.facebook.com") == true

doAssert parseBlacklistLine("con ads").matched("ads.example.org") == true
doAssert parseBlacklistLine("con ads").matched("some.ads.example.org") == true

doAssert parseBlacklistLine("eql example.org").matched("example.org") == true

doAssert loadListFromStr("#eql some stuff\neql example.org")[0].matched("example.org") == true
doAssert loadListFromStr("\neql example.org")[0].matched("example.org") == true
