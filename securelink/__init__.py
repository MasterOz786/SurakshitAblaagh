"""
Securelink - A secure tunnel library for multiple services over a single port using QUIC.
"""

from .server import Server, GetBaseTLSConfig, NewHTTPEchoServer
from .certificate import (
    Certificate,
    NewCertConfig,
    NewCA,
    NewDefaultCertificationConfig,
    NewDefaultCertificationConfigWithDefaultTemplate,
    BuildCertPEM,
    GetCertTemplate,
    GetSignatureAlgorithm,
    Unmarshal,
)
from .keys import (
    KeyPair,
    KeyType,
    KeyLength,
    NewKeyPair,
    NewRSA,
    NewEc,
    NewEd25519,
    UnmarshalKeyPair,
)
from .token import GetToken, ReadToken
from .transport import NetTransport, StartMemberlist
from .vars import (
    DefaultCertLifeTime,
    get_default_key_type as DefaultKeyType,
    get_default_key_length as DefaultKeyLength,
    ErrKeyConfigNotCompatible,
)

__all__ = [
    "Server",
    "GetBaseTLSConfig",
    "NewHTTPEchoServer",
    "Certificate",
    "NewCertConfig",
    "NewCA",
    "NewDefaultCertificationConfig",
    "NewDefaultCertificationConfigWithDefaultTemplate",
    "BuildCertPEM",
    "GetCertTemplate",
    "GetSignatureAlgorithm",
    "Unmarshal",
    "KeyPair",
    "KeyType",
    "KeyLength",
    "NewKeyPair",
    "NewRSA",
    "NewEc",
    "NewEd25519",
    "UnmarshalKeyPair",
    "GetToken",
    "ReadToken",
    "NetTransport",
    "StartMemberlist",
    "DefaultCertLifeTime",
    "DefaultKeyType",
    "DefaultKeyLength",
    "ErrKeyConfigNotCompatible",
]

