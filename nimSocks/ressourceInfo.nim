from types import ATYP
import net

type
  Ressource* = object
    kind*: ATYP
    value*: string

proc `$`*(res: Ressource): string =
  case res.kind
  of IP_V4_ADDRESS:
    var ip  = IpAddress(family: IpAddressFamily.IPV4)
    moveMem(addr ip.address_v4, unsafeAddr res.value[0], sizeof(ip.address_v4))
    return $(ip)
  of IP_V6_ADDRESS:
    var ip  = IpAddress(family: IpAddressFamily.IPv6)
    moveMem(addr ip.address_v6, unsafeAddr res.value[0], sizeof(ip.address_v6))
    return $(ip)
  of DOMAINNAME:
    return res.value