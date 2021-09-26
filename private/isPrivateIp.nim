import net

proc isPrivateIpv4*(ipAddress: IpAddress): bool {.inline.} =
  #  10.0.0.0    - 10.255.255.255  (10/8 prefix)
  #  172.16.0.0  - 172.31.255.255  (172.16/12 prefix)
  #  192.168.0.0 - 192.168.255.255 (192.168/16 prefix)
  #  127.0.0.0   - 127.255.255.255 # localhost
  #  169.254.0.0 - 169.254.255.255 # link local
  if ipAddress.address_v4[0] == 10:
    return true
  elif ipAddress.address_v4[0] == 172 and
      (ipAddress.address_v4[1] >= 16 and ipAddress.address_v4[1] <= 31):
    return true
  elif ipAddress.address_v4[0] == 192 and ipAddress.address_v4[1] == 168:
    return true
  elif ipAddress.address_v4[0] == 127:
    return true
  elif ipAddress.address_v4[0] == 169 and ipAddress.address_v4[1] == 254:
    return true
  else:
    return false

proc getWord(ipv6: array[16, byte], idx: range[0..8]): uint16 {.inline.} =
  result = ipv6[idx * 2]
  result = result.shl(8)
  result += ipv6[(idx * 2) + 1]

proc extractIpv4(ipv6: array[16, byte]): IpAddress {.inline.} =
    var ipv4Part = ipv6[12 .. 15]
    result = IpAddress(family: IPv4)
    moveMem(addr result.address_v4, addr ipv4Part[0], sizeof result.address_v4)

proc isPrivateIpv6*(ipAddress: IpAddress): bool {.inline.} =
  let first = ipAddress.address_v6.getWord(0)
  if first >= 0xfc00 and first <= 0xfdff: return true # Unique local address
  elif first >= 0xfe80 and first <= 0xfebf: return true # Link-local address.
  elif first == 0x2001:
    let second = ipAddress.address_v6.getWord(1)
    if second >= 0x20 and second <= 0x2f: return true # ORCHIDv2
    elif second == 0xdb8: return true # Documentation
  elif ipAddress.address_v6[15] == 0x01: return true # "::1" Loopback address to the local host.
  elif ipAddress.address_v6 == IpAddress(family: Ipv6).address_v6: ## all bytes zero "::" # TODO unsure if this is considered private
    return true
  elif ipAddress.address_v6.getWord(5) == 0xffff: # IPv4 mapped addresses.
    let ipv4 = ipAddress.address_v6.extractIpv4()
    return ipv4.isPrivateIpv4()
  elif ipAddress.address_v6.getWord(4) == 0xffff and ipAddress.address_v6.getWord(5) == 0x00: # IPv4 translated addresses.
    let ipv4 = ipAddress.address_v6.extractIpv4()
    return ipv4.isPrivateIpv4()
  elif ipAddress.address_v6.getWord(0) == 0x64 and ipAddress.address_v6.getWord(1) == 0xff9b: # IPv4/IPv6 translation.
    let ipv4 = ipAddress.address_v6.extractIpv4()
    return ipv4.isPrivateIpv4()
  elif ipAddress.address_v6[0 .. 11] == [0x00.byte, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]:
    let ipv4 = ipAddress.address_v6.extractIpv4()
    return ipv4.isPrivateIpv4()
  else:
    return false

proc isPrivate*(ipAddress: IpAddress): bool =
  ## Returns true if the ipAddress is a private address
  case ipAddress.family
  of IPv4:
    isPrivateIpv4(ipAddress)
  of IPv6:
    isPrivateIpv6(ipAddress)

proc isPrivate*(addressString: string): bool =
  isPrivate parseIpAddress(addressString)

when isMainModule:
  assert isPrivate("10.0.0.0") == true
  assert isPrivate("10.255.255.255") == true

  assert isPrivate("192.168.0.0") == true
  assert isPrivate("192.168.255.255") == true

  assert isPrivate("172.16.0.0") == true
  assert isPrivate("172.31.255.255") == true
  assert isPrivate("172.15.255.255") == false
  assert isPrivate("172.32.0.0") == false

  assert isPrivate("127.0.0.0") == true
  assert isPrivate("127.255.255.255") == true

  assert isPrivate("169.254.0.0") == true
  assert isPrivate("169.254.255.255") == true

  assert isPrivate("8.8.8.8") == false

  # ipv6 (its a mess...)
  assert isPrivate("::1") == true
  assert isPrivate("::") == true # TODO not sure

  assert isPrivate("::192.168.2.128") == true # handle this case even it its depricated
  assert isPrivate("::127.0.0.1") == true # handle this case even it its depricated

  # ::ffff:0.0.0.0  <-> ::ffff:255.255.255.255 # IPv4 mapped addresses.
  assert isPrivate("::ffff:192.168.2.128") == true

  # ::ffff:0:0.0.0.0 <-> ::ffff:0:255.255.255.255 # IPv4 translated addresses. (WHAT?!)
  assert isPrivate("::ffff:0:192.168.2.128") == true

  # 64:ff9b::0.0.0.0 <-> 64:ff9b::255.255.255.255	 # IPv4/IPv6 translation. (WHAT2 ?!?)
  assert isPrivate("64:ff9b::192.168.2.128") == true

  # Unique local address
  assert isPrivate("fc00::") == true
  assert isPrivate("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff") == true

  # Link-local address
  assert isPrivate("fe80::") == true
  assert isPrivate("febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff") == true

  # ORCHIDv2
  assert isPrivate("2001:20::") == true
  assert isPrivate("2001:2f:ffff:ffff:ffff:ffff:ffff:ffff") == true


