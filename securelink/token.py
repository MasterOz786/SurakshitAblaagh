"""Node token generation and parsing for temporary certificates."""

import json
import gzip
from typing import Tuple, Optional
import base91

from .certificate import Certificate, Unmarshal
from .common.addresses import Addr


def GetToken(server) -> str:
    """
    Returns a string representation of a temporary token (5 minutes validity).
    
    Args:
        server: Server instance with Certificate and AddrStruct
        
    Returns:
        Base91 encoded token string
    """
    from .certificate import NewDefaultCertificationConfigWithDefaultTemplate
    from datetime import timedelta
    
    cert_config = NewDefaultCertificationConfigWithDefaultTemplate("TOKEN")
    cert_config.life_time = timedelta(minutes=5)
    tmp_cert = server.Certificate.new_cert(cert_config, "TOKEN")

    token_obj = {
        "A": {
            "main_addr": server.AddrStruct.main_addr,
            "port": server.AddrStruct.port,
            "addrs": server.AddrStruct.addrs(),
        },
        "C": tmp_cert.marshal().hex(),
    }

    as_json = json.dumps(token_obj).encode()

    # Compress with gzip
    buf = gzip.compress(as_json, compresslevel=9)

    # Encode with base91
    return base91.encode(buf)


def ReadToken(token_string: str) -> Tuple[Addr, Certificate]:
    """
    Returns values from the token.
    
    It gives the server address of the signer and the temporary certificate for connection.
    
    Args:
        token_string: Base91 encoded token string
        
    Returns:
        Tuple of (Addr, Certificate)
        
    Raises:
        ValueError: If token parsing fails
    """
    from .common.addresses import Addr
    
    # Decode from base91
    try:
        compressed = base91.decode(token_string)
    except Exception as e:
        raise ValueError(f"failed to decode base91: {e}")

    # Decompress gzip
    try:
        as_json = gzip.decompress(compressed)
    except Exception as e:
        raise ValueError(f"failed to decompress gzip: {e}")

    # Parse JSON
    try:
        token_obj = json.loads(as_json.decode())
    except Exception as e:
        raise ValueError(f"failed to parse JSON: {e}")

    # Reconstruct Addr
    addr_data = token_obj["A"]
    addr = Addr(
        main_addr=addr_data["main_addr"],
        port=addr_data["port"],
        addrs=addr_data["addrs"],
    )

    # Unmarshal certificate
    try:
        cert_bytes = bytes.fromhex(token_obj["C"])
        certificate = Unmarshal(cert_bytes)
    except Exception as e:
        raise ValueError(f"failed to unmarshal certificate: {e}")

    return addr, certificate

