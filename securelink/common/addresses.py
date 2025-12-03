"""Network address management utilities."""

import ipaddress
import socket
from typing import List, Optional
import threading


class Addr:
    """Manages network addresses for the server."""

    def __init__(self, main_addr: str, port: int, addrs: List[str]):
        self._lock = threading.RLock()
        self._main_addr = main_addr
        self._port = port
        self._addrs = addrs

    @property
    def main_addr(self) -> str:
        """Get the main address."""
        with self._lock:
            return self._main_addr

    @property
    def port(self) -> int:
        """Get the port number."""
        with self._lock:
            return self._port

    def switch_main(self, index: int) -> Optional[str]:
        """Switch the main address to the address at the given index."""
        with self._lock:
            if index > len(self._addrs) - 1:
                return None
            self._main_addr = self._addrs[index]
            return str(self)

    def __str__(self) -> str:
        """Return string representation of address:port."""
        with self._lock:
            return f"{self._main_addr}:{self._port}"

    def network(self) -> str:
        """Return the network type."""
        return "udp"

    def addrs(self) -> List[str]:
        """Get all addresses."""
        with self._lock:
            return self._addrs.copy()

    def for_listener_broadcast(self) -> str:
        """Get address string for listener broadcast."""
        with self._lock:
            return f":{self._port}"

    def ip(self) -> Optional[ipaddress.IPv4Address | ipaddress.IPv6Address]:
        """Get the main IP address."""
        with self._lock:
            try:
                return ipaddress.ip_address(self._main_addr)
            except ValueError:
                return None

    def ips_v4(self) -> List[str]:
        """Get all IPv4 addresses."""
        with self._lock:
            ret = []
            for ip_str in self._addrs:
                try:
                    ip = ipaddress.ip_address(ip_str)
                    if isinstance(ip, ipaddress.IPv4Address):
                        ret.append(ip_str)
                except ValueError:
                    continue
            return ret

    def ips_v6(self) -> List[str]:
        """Get all IPv6 addresses."""
        with self._lock:
            ret = []
            for ip_str in self._addrs:
                try:
                    ip = ipaddress.ip_address(ip_str)
                    if isinstance(ip, ipaddress.IPv6Address):
                        ret.append(ip_str)
                except ValueError:
                    continue
            return ret

    def udp_addr(self) -> tuple:
        """Get UDP address tuple (host, port)."""
        return (self._main_addr, self._port)

    def must_udp_addr(self) -> tuple:
        """Get UDP address tuple, guaranteed to succeed."""
        return self.udp_addr()


def GetAddresses() -> List[str]:
    """Get all global unicast addresses from network interfaces."""
    ret = []
    try:
        interfaces = socket.getaddrinfo(socket.gethostname(), None)
        for interface in interfaces:
            ip_str = interface[4][0]
            try:
                ip = ipaddress.ip_address(ip_str)
                if ip.is_global:
                    if ip_str not in ret:
                        ret.append(ip_str)
            except ValueError:
                continue
    except Exception:
        pass

    # Also try getting interfaces directly
    try:
        for interface_name in socket.if_nameindex():
            addrs = socket.getaddrinfo(interface_name[1], None)
            for addr in addrs:
                ip_str = addr[4][0]
                try:
                    ip = ipaddress.ip_address(ip_str)
                    if ip.is_global:
                        if ip_str not in ret:
                            ret.append(ip_str)
                except ValueError:
                    continue
    except Exception:
        pass

    # Fallback: get localhost if nothing found
    if not ret:
        ret.append("127.0.0.1")

    return ret


def NewAddr(port: int) -> Addr:
    """Create a new Addr instance with the given port."""
    addrs = GetAddresses()
    if not addrs:
        raise ValueError("no address found")

    return Addr(
        main_addr=addrs[0],
        port=port,
        addrs=addrs,
    )

