"""Key pair generation and management for RSA, EC, and Ed25519."""

import json
from enum import Enum
from typing import Optional, Any
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import nacl.signing


class KeyType(str, Enum):
    """Key type enumeration."""
    ED25519 = "ed25519 Elliptic Curve"
    RSA = "RSA"
    EC = "NIST Elliptic Curve"


class KeyLength(str, Enum):
    """Key length enumeration."""
    ED25519 = "EC 25519"
    RSA2048 = "RSA 2048"
    RSA3072 = "RSA 3072"
    RSA4096 = "RSA 4096"
    RSA8192 = "RSA 8192"
    EC256 = "EC 256"
    EC384 = "EC 384"
    EC521 = "EC 521"


class KeyPair:
    """Manages different types and sizes of cryptographic keys."""

    def __init__(self, key_type: KeyType, key_length: KeyLength):
        self.type = key_type
        self.length = key_length
        self.private: Optional[Any] = None
        self.public: Optional[Any] = None

    def get_private_der(self) -> bytes:
        """Get the private key as DER encoded bytes."""
        if self.private is None:
            raise ValueError("private key not set")
        
        # All key types use PKCS8 for consistency
        return self.private.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    def get_private_pem(self) -> bytes:
        """Get the private key as PEM encoded bytes."""
        der = self.get_private_der()
        
        if self.type == KeyType.ED25519:
            pem_type = "PRIVATE KEY"
        elif self.type == KeyType.EC:
            pem_type = "EC PRIVATE KEY"
        else:  # RSA
            pem_type = "RSA PRIVATE KEY"
        
        return self.private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    def marshal(self) -> bytes:
        """Marshal the KeyPair to bytes for transport."""
        export = {
            "Type": self.type.value,
            "Length": self.length.value,
            "Private": self.get_private_der().hex(),
        }
        return json.dumps(export).encode()


def NewKeyPair(key_type: KeyType, key_length: KeyLength) -> KeyPair:
    """Build a new key pair with the given options."""
    if key_type == KeyType.ED25519:
        return NewEd25519()
    elif key_type == KeyType.EC:
        return NewEc(key_length)
    elif key_type == KeyType.RSA:
        return NewRSA(key_length)
    else:
        raise ValueError(f"the given type is not valid: {key_type}")


def NewRSA(key_length: KeyLength) -> KeyPair:
    """Create a new RSA key pair of the given size."""
    length_map = {
        KeyLength.RSA2048: 2048,
        KeyLength.RSA3072: 3072,
        KeyLength.RSA4096: 4096,
        KeyLength.RSA8192: 8192,
    }
    
    length = length_map.get(key_length)
    if length is None:
        raise ValueError(f"invalid RSA key length: {key_length}")
    
    ret = KeyPair(KeyType.RSA, key_length)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=length,
        backend=default_backend()
    )
    
    ret.private = private_key
    ret.public = private_key.public_key()
    
    return ret


def NewEc(key_length: KeyLength) -> KeyPair:
    """Create a new elliptic curve key pair of the given size."""
    curve_map = {
        KeyLength.EC256: ec.SECP256R1(),
        KeyLength.EC384: ec.SECP384R1(),
        KeyLength.EC521: ec.SECP521R1(),
    }
    
    curve = curve_map.get(key_length)
    if curve is None:
        raise ValueError(f"invalid EC key length: {key_length}")
    
    ret = KeyPair(KeyType.EC, key_length)
    private_key = ec.generate_private_key(curve, default_backend())
    
    ret.private = private_key
    ret.public = private_key.public_key()
    
    return ret


def NewEd25519() -> KeyPair:
    """Create a new Ed25519 key pair."""
    from cryptography.hazmat.primitives.asymmetric import ed25519 as crypto_ed25519
    
    ret = KeyPair(KeyType.ED25519, KeyLength.ED25519)
    
    # Use cryptography's Ed25519 for compatibility with x509
    private_key = crypto_ed25519.Ed25519PrivateKey.generate()
    ret.private = private_key
    ret.public = private_key.public_key()
    
    return ret


def UnmarshalKeyPair(input_bytes: bytes) -> KeyPair:
    """Rebuild a KeyPair from marshaled bytes."""
    try:
        export = json.loads(input_bytes.decode())
    except Exception as e:
        raise ValueError(f"failed to unmarshal key pair: {e}")
    
    key_type = KeyType(export["Type"])
    key_length = KeyLength(export["Length"])
    
    ret = KeyPair(key_type, key_length)
    
    private_der = bytes.fromhex(export["Private"])
    
    if key_type == KeyType.ED25519:
        from cryptography.hazmat.primitives.asymmetric import ed25519 as crypto_ed25519
        ret.private = serialization.load_der_private_key(
            private_der,
            password=None,
            backend=default_backend()
        )
        ret.public = ret.private.public_key()
    elif key_type == KeyType.RSA:
        ret.private = serialization.load_der_private_key(
            private_der,
            password=None,
            backend=default_backend()
        )
        ret.public = ret.private.public_key()
    elif key_type == KeyType.EC:
        ret.private = serialization.load_der_private_key(
            private_der,
            password=None,
            backend=default_backend()
        )
        ret.public = ret.private.public_key()
    else:
        raise ValueError(f"unknown key type: {key_type}")
    
    return ret

