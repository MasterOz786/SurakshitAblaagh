# Securelink Python Port

This is a Python port of the Securelink Go library. It provides secure tunnels between services using QUIC over a single port.

## Installation

```bash
pip install -r requirements.txt
```

Or install the package:

```bash
pip install -e .
```

## Dependencies

- `aioquic>=0.9.20` - QUIC protocol support
- `cryptography>=41.0.0` - TLS, X.509, keys
- `pynacl>=1.5.0` - Ed25519 support
- `base91>=1.0.1` - Base91 encoding
- `structlog>=23.0.0` - Structured logging (optional)

## Usage

### Basic Example

```python
import asyncio
from securelink import (
    Server,
    NewCA,
    NewDefaultCertificationConfig,
    GetBaseTLSConfig,
)

async def main():
    # Build the CA
    conf = NewDefaultCertificationConfig()
    ca = NewCA(conf, "ca")
    
    # Build server certificate
    server_cert = ca.new_cert(None, "server", "localhost")
    
    # Build TLS configuration
    tls_config = GetBaseTLSConfig("localhost", server_cert)
    
    # Create server
    ctx = asyncio.get_event_loop()
    server = await Server.NewServer(ctx, 3815, tls_config, server_cert)
    
    # Create a service listener
    listener = server.NewListener("echo service")
    
    # Handle connections
    async def handle_conn(conn):
        data = await conn.read(1024)
        await conn.write(data)
        conn.close()
    
    # Accept loop
    while True:
        conn = await listener.accept()
        asyncio.create_task(handle_conn(conn))

if __name__ == "__main__":
    asyncio.run(main())
```

### Certificate Management

```python
from securelink import (
    NewCA,
    NewDefaultCertificationConfig,
    KeyType,
    KeyLength,
)

# Create CA with specific key type
conf = NewDefaultCertificationConfig()
conf.key_type = KeyType.EC
conf.key_length = KeyLength.EC256
ca = NewCA(conf, "my-ca")

# Create signed certificate
cert = ca.new_cert(None, "example.com", "*.example.com")
```

## Differences from Go Version

1. **Async/Await**: Uses Python's `asyncio` instead of Go's goroutines
2. **QUIC Library**: Uses `aioquic` instead of `quic-go` (may have different API)
3. **Memberlist**: Full memberlist integration requires a Python memberlist library
4. **Type System**: Uses Python type hints instead of Go's static typing

## Testing

```bash
pytest tests/
```

## Status

This is a port of the Go codebase. Some features may need additional work:
- QUIC implementation may need refinement based on aioquic API
- Memberlist integration is a placeholder
- Full test coverage needs to be implemented

## Notes

- The Go files are preserved alongside the Python implementation
- Both implementations provide the same functionality
- The Python version uses async/await patterns throughout

