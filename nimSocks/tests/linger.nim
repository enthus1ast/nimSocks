
when defined POSIX:
  import posix
when defined WINDOWS:
  import winlean


type

  Linger = object {.pure, final.}
      l_onoff: cint #    /* linger active */
      l_linger:  int #;   /* how many seconds to linger for */



proc setLinger(socket: AsyncSocket, enabled: bool, timeout: int): bool =
  var linger = Linger()
  linger.l_onoff = enabled.cint
  linger.l_linger = timeout.cint
  echo linger
  var res = setSockOpt(socket.getFd(), SOL_SOCKET, SO_LINGER, addr linger, sizeof(linger).SockLen)
  if res != 0: 
    return false
  return true

proc getLinger(socket: AsyncSocket): tuple[enabled: bool, timmeout: int] =
  var linger = Linger()
  var lingerLen = sizeof(linger).SockLen
  var res = getSockOpt(socket.getFd(), SOL_SOCKET, SO_LINGER, addr linger, addr lingerLen)
  if res != 0: 
    return (false, 0)
  return (linger.l_onoff.bool, linger.l_linger)
  