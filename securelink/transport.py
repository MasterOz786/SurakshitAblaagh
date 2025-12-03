"""Memberlist transport implementation over QUIC."""

import asyncio
import logging
from typing import Optional
from dataclasses import dataclass

from .server import Server


TCP_SERVICE_NAME = "TCP memberlist"
UDP_SERVICE_NAME = "UDP memberlist"
QUIC_PACKET_BUF_SIZE = 2 * 1024 * 1024
QUIC_TIMEOUT = 1.0  # 1 second


@dataclass
class Packet:
    """Represents a network packet."""
    buf: bytes
    from_addr: tuple
    timestamp: float


class NetTransport:
    """Transport implementation that uses QUIC for packet and stream operations."""

    def __init__(self, server: Server):
        self.server = server
        self.packet_ch = asyncio.Queue()
        self.stream_ch = asyncio.Queue()
        self.logger = logging.getLogger(__name__)
        self.shutdown = False
        self.tcp_listener: Optional[object] = None
        self.udp_listener: Optional[object] = None

    @classmethod
    async def new_net_transport(cls, server: Server) -> 'NetTransport':
        """Create a new net transport with the given configuration."""
        tcp_ln = server.NewListener(TCP_SERVICE_NAME)
        if tcp_ln is None:
            raise ValueError("Failed to start TCP listener")

        udp_ln = server.NewListener(UDP_SERVICE_NAME)
        if udp_ln is None:
            raise ValueError("Failed to start UDP listener")

        t = cls(server)
        t.tcp_listener = tcp_ln
        t.udp_listener = udp_ln

        # Start listening tasks
        asyncio.create_task(t.tcp_listen(tcp_ln))
        asyncio.create_task(t.udp_listen(udp_ln))

        return t

    def get_auto_bind_port(self) -> int:
        """Get the bind port that was automatically given by the kernel."""
        return self.server.AddrStruct.port

    def final_advertise_addr(self, ip: str, port: int) -> tuple:
        """Get the final advertise address."""
        advertise_addr = self.server.AddrStruct.main_addr
        advertise_port = self.get_auto_bind_port()
        return (advertise_addr, advertise_port)

    async def write_to(self, data: bytes, addr: str) -> float:
        """Write data to the given address."""
        import socket
        try:
            # Parse address
            if ':' in addr:
                host, port_str = addr.rsplit(':', 1)
                port = int(port_str)
            else:
                host = addr
                port = 0
            
            udp_addr = (host, port)
            
            # Dial using server's Dial method
            conn = await self.server.Dial(udp_addr, UDP_SERVICE_NAME, QUIC_TIMEOUT)
            if conn is None:
                raise ConnectionError("failed to dial")
            
            await conn.write(data)
            import time
            return time.time()
        except Exception as e:
            self.logger.error(f"Error writing to {addr}: {e}")
            raise

    def packet_channel(self):
        """Get the packet channel."""
        return self.packet_ch

    async def dial_timeout(self, addr: str, timeout: float):
        """Dial to the given address with timeout."""
        import socket
        try:
            # Parse address
            if ':' in addr:
                host, port_str = addr.rsplit(':', 1)
                port = int(port_str)
            else:
                host = addr
                port = 0
            
            udp_addr = (host, port)
            
            conn = await self.server.Dial(udp_addr, TCP_SERVICE_NAME, timeout)
            return conn
        except Exception as e:
            self.logger.error(f"Error dialing {addr}: {e}")
            raise

    def stream_channel(self):
        """Get the stream channel."""
        return self.stream_ch

    async def shutdown_transport(self):
        """Shutdown the transport."""
        self.shutdown = True
        if self.tcp_listener:
            self.tcp_listener.close()
        if self.udp_listener:
            self.udp_listener.close()

    async def tcp_listen(self, ln):
        """TCP listen loop that accepts incoming connections."""
        base_delay = 0.005  # 5ms
        max_delay = 1.0  # 1 second
        loop_delay = 0

        while not self.shutdown:
            try:
                conn = await ln.accept()
                loop_delay = 0  # Reset delay on success
                await self.stream_ch.put(conn)
            except Exception as e:
                if self.shutdown:
                    break

                if loop_delay == 0:
                    loop_delay = base_delay
                else:
                    loop_delay = min(loop_delay * 2, max_delay)

                self.logger.error(f"memberlist: Error accepting connection: {e}")
                await asyncio.sleep(loop_delay)

    async def udp_listen(self, ln):
        """UDP listen loop that accepts incoming packets."""
        import time
        
        while not self.shutdown:
            try:
                conn = await ln.accept()
                if self.shutdown:
                    break

                buf = bytearray(QUIC_PACKET_BUF_SIZE)
                n = await conn.read(len(buf))
                ts = time.time()

                if n < 1:
                    self.logger.error(f"memberlist: UDP packet too short ({n} bytes)")
                    continue

                # Ingest the packet
                packet = Packet(
                    buf=buf[:n],
                    from_addr=conn.remote_addr(),
                    timestamp=ts,
                )
                await self.packet_ch.put(packet)

            except Exception as e:
                if self.shutdown:
                    break
                self.logger.error(f"memberlist: Error reading UDP packet: {e}")


async def StartMemberlist(server: Server, config=None):
    """
    Start memberlist with the given configuration.
    
    Note: This is a placeholder. Full memberlist integration would require
    a Python memberlist library or custom implementation.
    """
    if config is None:
        raise ValueError("config can't be nil")

    tr = await NetTransport.new_net_transport(server)
    
    # Note: Memberlist integration would go here
    # For now, we just store the transport
    server.memberlist_transport = tr
    
    return tr

