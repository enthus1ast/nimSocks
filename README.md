# nimSocks
a filtering (standalone) SOCKS proxy server and client library for nim.

## Features client and server
- (SOCKS4, SOCKS4a server only), SOCKS5 
- password auth / no auth
- ipv4, ipv6, domain.
- SOCKS CONNECT (no bind, no udp atm)
- domain target white/black-listing
- static hosts

## SOCKS Compatibility Table

| Socks Version | TCP | UDP | IPv4 | IPv6 | Hostname |
| --- | :---: | :---: | :---: | :---: | :---: |
| SOCKS v4 | ✅ | ❌ | ✅ | ❌ | ❌ |
| SOCKS v4a | ✅ | ❌ | ✅ | ❌ | ✅ |
| SOCKS v5 | ✅ | ✅ | ✅ | ✅ | ✅ |

## nimSocks implementation
| lib | TCP connect | TCP accociate | UDP bind |
| --- | :---: | :---: | :---: |
|server | ✅ | ❌ | ❌ |
|client | ✅ | ❌ | ❌ |

| lib | SOCKS v4 | SOCKS v4a | SOCKS v5 |
| --- | :---: | :---: | :---: |
|server | ✅ | ✅ | ✅ |
|client | ❌ | ❌ | ✅ |

| auth | no auth | user/password |
| --- | :---: | :---: |
|server | ✅ | ✅ |
|client | ✅ | ✅ |


# server
## usage

```nim
  import nimSocks/server
  var proxy = newSocksServer()
  echo "SOCKS Proxy listens on: ", proxy.listenPort
  proxy.allowedSocksVersions = {SOCKS_V4, SOCKS_V5}
  proxy.allowedAuthMethods = {USERNAME_PASSWORD, NO_AUTHENTICATION_REQUIRED}

  ## Add a valid user / password combination
  proxy.addUser("hans", "peter")

  ## For a static host replacement:
  proxy.staticHosts.add("peter.peter", "example.org")

  asyncCheck proxy.serve()
  asyncCheck proxy.dumpThroughput()
  runForever()
```

## black and whitelisting example filter file 
(full domain match only)

for a good blacklist file use
https://raw.githubusercontent.com/notracking/hosts-blocklists/master/dnscrypt-proxy/dnscrypt-proxy.blacklist.txt

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
the client can "upgrade" your socket.

```nim
var sock = waitFor asyncnet.dial("127.0.0.1", Port 1080 ) # dial to the socks server 
assert true == waitFor sock.doSocksHandshake(
    username="username", 
    password="password", 
    methods={NO_AUTHENTICATION_REQUIRED, USERNAME_PASSWORD} # the "best" auth supported gets choosen by the server!
    ) 
assert true == waitFor sock.doSocksConnect("example.org", Port 80) # instruct the proxy to connect to target host (by tcp)

# Then do normal socket operations
sock.send("FOO")
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
 
## random examples
```
$ ncat --proxy 127.0.0.1:1080 --proxy-type socks5 --proxy-auth hans:peter  2a02:bbb:aaa:9daa:ff11:a4ff:aaaa:bbbb 9090
$ curl --socks5-basic --socks5 hans:peter@127.0.0.1:1080 google.de
```
