# nimSocks
a filtering (standalone) SOCKS proxy server and client library for nim.

## Features client and server
- SOCKS4, SOCKS4a, SOCKS5 
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

if there are whitelist* entries
the blacklist* gets skipped!


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

## proxy hopping
you could easily do "proxy hopping", 
by letting the first SOCKS server connect to the next,
then do handshake, connect, etc.


```nim
var sock = waitFor asyncnet.dial("firstSocks.loc", Port 1080 )
assert true == waitFor sock.doSocksHandshake(methods={NO_AUTHENTICATION_REQUIRED})
assert true == waitFor sock.doSocksConnect("secondSocks.loc", Port 1080) 

assert true == waitFor sock.doSocksHandshake(methods={NO_AUTHENTICATION_REQUIRED})
assert true == waitFor sock.doSocksConnect("mytarget.loc", Port 80) 

sock.send(FOO) # from here we speak to "mytarget.loc"
sock.close() # will destroy the whole tunnel
```


## getLocalAddr 
Since the SOCKS proxy server is acting on our behalf, 
we cannot use `sock.getLocalAddr` to aquire our address.
The server has to provides these data.

