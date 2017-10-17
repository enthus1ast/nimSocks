# nimSocks
a filtering (standalone) SOCKS proxy server and client library.

## Features client and server
- SOCKS5 (only atm)
- password auth / no auth
- ipv4, ipv6, domain.
- SOCKS CONNECT (no bind, no udp atm)
- domain target white/black-listing
- static hosts


# example filter file 
(full domain match only)

files 
- whitelist.txt
- blacklist.txt

```
nim-lang.org
forum.nim-lang.org
```


# example "fancy" filter 

files 
- whitelistFancy.txt
- blacklistFancy.txt


```

# '#' is a comment

# all domains containing nim
con nim

# ending with
end nim-lang.org
end wikipedia.org

# exact match
eql github.org

# startswith
sta foo.baa
```


# static hosts
fill the `staticHosts` table to always resolve to given ip/dns

```nim
#...
proxy.staticHosts.add("foo.loc", "example.org")
proxy.staticHosts.add("baa.loc", "192.168.1.1")
#...
```