"""Main server implementation for QUIC-based secure tunneling."""

import asyncio
import hashlib
import logging
import socket
from typing import Dict, Optional, List
from contextlib import asynccontextmanager
from cryptography.hazmat.primitives import serialization
try:
    from aioquic.asyncio import connect, serve
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.connection import QuicConnection
    from aioquic.quic.events import StreamDataReceived, StreamReset
    from aioquic.tls import SessionTicket
except ImportError:
    # Fallback if aioquic is not available
    pass

from .certificate import Certificate
from .common.addresses import Addr, NewAddr
from .vars import serviceNameSize


serviceNameSize = 8


class LocalConn:
    """Local connection wrapper for QUIC streams."""

    def __init__(self, stream, session):
        self.stream = stream
        self.session = session

    def local_addr(self):
        """Get local address."""
        return self.session._local_addr

    def remote_addr(self):
        """Get remote address."""
        return self.session._remote_addr

    async def read(self, n: int = -1) -> bytes:
        """Read data from the stream."""
        return await self.stream.read(n)

    async def write(self, data: bytes) -> int:
        """Write data to the stream."""
        return await self.stream.write(data)

    def close(self):
        """Close the connection."""
        self.stream.close()
        self.session.close()


class LocalListener:
    """Local listener for service connections."""

    def __init__(self, name: str, server: 'Server'):
        self.name = name
        self.server = server
        self.conn_queue = asyncio.Queue(maxsize=32)
        self._closed = False

    async def accept(self) -> LocalConn:
        """Accept a new connection."""
        if self._closed:
            raise ValueError("the listener looks closed")
        return await self.conn_queue.get()

    def close(self):
        """Close the listener."""
        self._closed = True
        # Remove from server's service listeners
        with self.server.lock:
            hash_obj = hashlib.blake2b(digest_size=serviceNameSize)
            hash_obj.update(self.name.encode())
            listener_key = hash_obj.hexdigest()
            if listener_key in self.server.ServiceListeners:
                del self.server.ServiceListeners[listener_key]


class Server:
    """Server provides a way to have many services on a single open port."""

    def __init__(
        self,
        ctx,
        port: int,
        tls_config,
        cert: Certificate,
    ):
        self.ctx = ctx
        self.AddrStruct = NewAddr(port)
        self.Certificate = cert
        self.TLSConfig = tls_config
        self.ServiceListeners: Dict[str, LocalListener] = {}
        self.Listeners: List = []
        self.packet_conns: List = []
        self.incoming_sessions: Dict[str, QuicConnection] = {}
        self.outgoing_sessions: Dict[str, QuicConnection] = {}
        self.lock = asyncio.Lock()
        self.Memberlist = None

        # Setup logging
        self.Logger = logging.getLogger(__name__)
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        self.Logger.addHandler(handler)
        self.Logger.setLevel(logging.INFO)

    @classmethod
    async def NewServer(
        cls,
        ctx,
        port: int,
        tls_config,
        cert: Certificate,
    ) -> 'Server':
        """Build a new server."""
        server = cls(ctx, port, tls_config, cert)

        # Setup QUIC listeners
        quic_config = QuicConfiguration(
            is_client=False,
            max_datagram_frame_size=65536,
        )
        quic_config.load_cert_chain(*cert.get_tls_certificate())

        for addr_str in server.AddrStruct.addrs():
            try:
                ip = socket.gethostbyname(addr_str) if not addr_str.startswith('[') else addr_str
                # Create UDP socket
                sock = socket.socket(socket.AF_INET6 if ':' in ip else socket.AF_INET, socket.SOCK_DGRAM)
                sock.bind((ip, port))
                
                # Note: aioquic uses different API, this is a simplified version
                # In production, you'd use aioquic's serve() function
                server.packet_conns.append(sock)
                
                # Start accept loop
                asyncio.create_task(server._accept_loop(sock, quic_config))
            except Exception as e:
                server.Logger.error(f"Failed to bind to {addr_str}:{port}: {e}")
                raise

        server.Logger.info(f"server started on port {port}")
        return server

    async def _accept_loop(self, sock, quic_config):
        """Accept loop for incoming connections."""
        # This is a simplified version - aioquic has its own event loop
        # In practice, you'd use aioquic's serve() function
        while not self.ctx.done():
            try:
                # Receive UDP packet
                data, addr = sock.recvfrom(65536)
                # Process QUIC packet (simplified - actual implementation is more complex)
                # For now, we'll use a placeholder
                pass
            except Exception as e:
                if not self.ctx.done():
                    self.Logger.debug(f"Error in accept loop: {e}")

    async def handle_conn(self, session: QuicConnection, incoming: bool):
        """Handle a QUIC connection."""
        if incoming:
            async def remove_session():
                async with self.lock:
                    addr_str = str(session._remote_addr)
                    if addr_str in self.incoming_sessions:
                        del self.incoming_sessions[addr_str]
            # Note: In real implementation, this would be called on session close

        while True:
            try:
                # Get stream from session (simplified)
                # In aioquic, you'd handle QuicEvent objects
                stream = await self._get_stream(session)
                if stream is None:
                    break

                target = await self.get_target(stream)
                if target is None:
                    session.close()
                    return

                async with self.lock:
                    listener = self.ServiceListeners.get(target)
                
                if listener is None:
                    self.Logger.debug(f"target listener {target} is nil")
                    session.close()
                    return

                conn = LocalConn(stream, session)
                await listener.conn_queue.put(conn)

            except Exception as e:
                self.Logger.debug(f"Error handling connection: {e}")
                session.close()
                return

    async def _get_stream(self, session):
        """Get a stream from the session (placeholder)."""
        # In real implementation, this would handle QuicEvent.StreamDataReceived
        # For now, return None as placeholder
        return None

    async def get_target(self, stream) -> Optional[str]:
        """Read the first serviceNameSize bytes to get the target service name."""
        check_buff = await stream.read(serviceNameSize)
        if len(check_buff) != serviceNameSize:
            return None
        return check_buff.hex()

    async def Dial(self, addr: tuple, service_name: str, timeout: float) -> LocalConn:
        """Dial to another server and set a prefix to access specific registered service."""
        session = await self.dial(addr, timeout)
        if session is None:
            raise ConnectionError("failed to dial")

        # Open stream
        stream_id = session.get_next_available_stream_id()
        stream = session._get_or_create_stream(stream_id)
        
        # Set deadline
        # Note: aioquic handles timeouts differently

        # Hash service name
        hash_obj = hashlib.blake2b(digest_size=serviceNameSize)
        hash_obj.update(service_name.encode())
        key = hash_obj.digest()

        await stream.write(key)

        return LocalConn(stream, session)

    async def dial(self, addr: tuple, timeout: float) -> Optional[QuicConnection]:
        """Dial to create a QUIC session."""
        async with self.lock:
            addr_str = f"{addr[0]}:{addr[1]}"
            session = self.outgoing_sessions.get(addr_str)
            if session is not None:
                return session

        # Check incoming sessions
        async with self.lock:
            session = self.incoming_sessions.get(addr_str)
            if session is not None:
                return session

        # Create new connection
        try:
            from cryptography.hazmat.primitives import serialization
            quic_config = QuicConfiguration(is_client=True)
            ca_cert = self.Certificate.get_cert_pool()
            if ca_cert:
                quic_config.load_verify_locations(cadata=ca_cert.public_bytes(serialization.Encoding.PEM))
        except ImportError:
            # aioquic not available
            quic_config = None
        
        # Use aioquic's connect function
        # This is simplified - actual implementation would use aioquic.connect()
        try:
            # Placeholder - actual QUIC connection setup
            session = None  # Would be created by aioquic.connect()
            
            async with self.lock:
                self.outgoing_sessions[addr_str] = session

            # Handle connection in background
            asyncio.create_task(self.handle_conn(session, False))

            # Cleanup on close
            def cleanup():
                async def _cleanup():
                    async with self.lock:
                        if addr_str in self.outgoing_sessions:
                            del self.outgoing_sessions[addr_str]
                asyncio.create_task(_cleanup())
            
            # Note: Would register cleanup callback on session close
            
            return session
        except Exception as e:
            self.Logger.error(f"Failed to dial {addr}: {e}")
            return None

    def NewListener(self, name: str) -> LocalListener:
        """Create a new listener for a service."""
        hash_obj = hashlib.blake2b(digest_size=serviceNameSize)
        hash_obj.update(name.encode())
        key = hash_obj.hexdigest()

        async def check_and_create():
            async with self.lock:
                if key in self.ServiceListeners:
                    raise ValueError("a listener with the same name is already registered")

                ll = LocalListener(name, self)
                self.ServiceListeners[key] = ll
                return ll

        # Run in event loop
        loop = asyncio.get_event_loop()
        return loop.run_until_complete(check_and_create())

    def Ctx(self):
        """Get the context."""
        return self.ctx

    def Close(self):
        """Close the server and all listeners."""
        # Close all service listeners
        for listener in list(self.ServiceListeners.values()):
            listener.close()

        # Close all sessions
        for session in list(self.incoming_sessions.values()):
            session.close()
        for session in list(self.outgoing_sessions.values()):
            session.close()

        # Close all listeners
        for listener in self.Listeners:
            listener.close()

        # Close all packet connections
        for pc in self.packet_conns:
            pc.close()


def GetBaseTLSConfig(host: str, cert: Certificate):
    """Get a base TLS configuration."""
    import ssl
    import tempfile
    import os

    
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    
    # Get cert and key PEM
    cert_pem = cert.get_cert_pem()
    key_pem = cert.get_key_pem()
    
    # Use temporary files for certificate and key
    # Note: In production, you might want to manage these files differently
    with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.pem') as cert_file:
        cert_file.write(cert_pem)
        cert_path = cert_file.name
    
    with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.pem') as key_file:
        key_file.write(key_pem)
        key_path = key_file.name
    
    try:
        # Load certificate chain from files
        context.load_cert_chain(cert_path, key_path)
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = False  # We handle this manually
        
        # Load CA certs
        ca_cert = cert.get_cert_pool()
        if ca_cert and hasattr(ca_cert, 'public_bytes'):
            context.load_verify_locations(cadata=ca_cert.public_bytes(serialization.Encoding.PEM))
    finally:
        # Clean up temp files
        try:
            os.unlink(cert_path)
            os.unlink(key_path)
        except:
            pass
    
    return context


def NewHTTPEchoServer(ln):
    """Prepare an Echo server (placeholder for HTTP framework integration)."""
    # In Go, this returns an echo.Echo instance
    # In Python, you might use FastAPI or Flask
    # This is a placeholder
    return None

