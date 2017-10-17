# nimSocks
a filtering (standalone) SOCKS proxy server and client library.

## Features client and server
- SOCKS5 (only atm)
- password auth / no auth
- ipv4, ipv6, domain.
- SOCKS CONNECT (no bind, no udp atm)
- domain target white/black-listing
- static hosts

# server
## example filter file 
(full domain match only)

files 
- whitelist.txt
- blacklist.txt

```
nim-lang.org
forum.nim-lang.org
```


## example "fancy" filter 

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


## static hosts
fill the `staticHosts` table to always resolve to given ip/dns

```nim
#...
proxy.staticHosts.add("foo.loc", "example.org")
proxy.staticHosts.add("baa.loc", "192.168.1.1")
#...
```

# client
the client can only "upgrade" your socket atm.

```nim
var sock = waitFor asyncnet.dial("127.0.0.1", Port 1080 ) # dial to the socks server 
assert true == waitFor sock.doSocksHandshake(
    username="username", 
    password="password", 
    methods={NO_AUTHENTICATION_REQUIRED, USERNAME_PASSWORD} # the "best" auth supported gets choosen by the server!
    ) 
assert true == waitFor sock.doSocksConnect("example.org", Port 80) # instruct the proxy to connect to target host (by tcp)

# Then do normal socket operations
sock.send(FOO)
```
