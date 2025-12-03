"""Certificate and CA management for PKI infrastructure."""

import re
import json
from datetime import datetime, timedelta
from typing import Optional, List
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
import ipaddress

from .keys import KeyPair, KeyType, KeyLength
from .vars import DefaultCertLifeTime, ErrKeyConfigNotCompatible


class Certificate:
    """Provides an easy way to use certificates with TLS."""

    def __init__(
        self,
        cert: x509.Certificate,
        key_pair: KeyPair,
        ca_cert: Optional[x509.Certificate] = None,
        cert_pool: Optional[x509.Certificate] = None,
        is_ca: bool = False,
    ):
        self.cert = cert
        self.key_pair = key_pair
        self.ca_cert = ca_cert
        self.cert_pool = cert_pool
        self.is_ca = is_ca

    def id(self) -> int:
        """Return the certificate serial number."""
        return int(self.cert.serial_number)

    def get_cert_pem(self) -> bytes:
        """Get the certificate as PEM encoded bytes."""
        return self.cert.public_bytes(serialization.Encoding.PEM)

    def get_key_pem(self) -> bytes:
        """Get the private key as PEM encoded bytes."""
        return self.key_pair.get_private_pem()

    def get_tls_certificate(self):
        """Get a TLS certificate object for use with TLS config."""
        cert_pem = self.get_cert_pem()
        key_pem = self.get_key_pem()
        
        # Return tuple for use with SSLContext.load_cert_chain
        # Note: load_cert_chain expects file paths, but we can use BytesIO
        from io import BytesIO
        return (BytesIO(cert_pem), BytesIO(key_pem))

    def get_cert_pool(self):
        """Get a certificate pool containing the CA certificate."""
        # For Python, we return the CA cert directly
        # The caller can use it to build an SSLContext
        return self.cert_pool if self.cert_pool else self.ca_cert

    def marshal(self) -> bytes:
        """Convert the Certificate to bytes for transport."""
        export = {
            "Cert": self.cert.public_bytes(serialization.Encoding.DER).hex(),
            "KeyPair": self.key_pair.marshal().hex(),
            "CACert": (self.ca_cert.public_bytes(serialization.Encoding.DER).hex() 
                      if self.ca_cert else ""),
        }
        return json.dumps(export).encode()

    def new_cert(self, config: Optional['NewCertConfig'], *names: str) -> 'Certificate':
        """Create a new signed certificate with the given domain names."""
        if not self.is_ca:
            raise ValueError("this is not a CA")

        if config is None:
            config = NewDefaultCertificationConfig()

        config.parent = self

        if config.cert_pool is None:
            config.cert_pool = self.get_cert_pool()
        # Note: In Go, AppendCertsFromPEM is used, but in Python we handle this differently

        return new_cert(config, *names)


class NewCertConfig:
    """Configuration for building a new certificate."""

    def __init__(self):
        self.is_ca = False
        self.is_wildcard = True
        self.cert_template: Optional[object] = None
        self.parent: Optional[Certificate] = None
        self.life_time = DefaultCertLifeTime
        from .vars import get_default_key_type, get_default_key_length
        self.key_type = get_default_key_type()
        self.key_length = get_default_key_length()
        self.public_key: Optional[KeyPair] = None
        self.cert_pool: Optional[x509.Certificate] = None

    def valid(self) -> None:
        """Validate the configuration."""
        if self.cert_template is None:
            raise ValueError("the template can't be empty")

        if self.parent is None:
            if self.key_type is None or self.key_length is None:
                from .vars import get_default_key_type, get_default_key_length
                self.key_type = get_default_key_type()
                self.key_length = get_default_key_length()
            self._gen_parent()

        if self.cert_pool is None:
            if self.parent:
                self.cert_pool = self.parent.get_cert_pool()

        if self.public_key is None:
            from .keys import NewKeyPair
            self.public_key = NewKeyPair(self.key_type, self.key_length)

    def _gen_parent(self):
        """Generate a parent certificate if none exists."""
        from .keys import NewKeyPair
        key_pair = NewKeyPair(self.key_type, self.key_length)

        parent = Certificate(
            cert=self.cert_template,
            key_pair=key_pair,
            is_ca=True,
        )

        if self.public_key is None:
            self.public_key = key_pair

        self.is_ca = True
        self.is_wildcard = True
        self.parent = parent

    def _wildcard(self):
        """Add wildcard domains to the certificate template."""
        if not self.is_wildcard or self.cert_template is None:
            return

        wildcard_match_regexp = re.compile(r"^\*\.")

        # Check if global wildcard is already set
        for name in self.cert_template.subject_alternative_name.get_values_for_type(x509.DNSName):
            if name == "*":
                return

        # Add wildcard for each domain
        dns_names = list(self.cert_template.subject_alternative_name.get_values_for_type(x509.DNSName))
        for name in dns_names:
            if not wildcard_match_regexp.match(name):
                to_add = f"*.{name}"
                if to_add not in dns_names:
                    dns_names.append(to_add)

        # Update the certificate template with new DNS names
        # This requires rebuilding the certificate builder
        pass  # Will be handled in new_cert function


def BuildCertPEM(cert: x509.Certificate) -> bytes:
    """Build a PEM encoded x509 certificate."""
    return cert.public_bytes(serialization.Encoding.PEM)


def GetSignatureAlgorithm(key_type: KeyType, key_length: KeyLength) -> Optional[hashes.HashAlgorithm]:
    """Get the signature algorithm for the given key type and size."""
    if key_type == KeyType.ED25519:
        return None  # Ed25519 doesn't use a hash algorithm
    elif key_type == KeyType.RSA:
        if key_length == KeyLength.RSA2048:
            return hashes.SHA256()
        elif key_length == KeyLength.RSA3072:
            return hashes.SHA384()
        elif key_length in (KeyLength.RSA4096, KeyLength.RSA8192):
            return hashes.SHA512()
    elif key_type == KeyType.EC:
        if key_length == KeyLength.EC256:
            return hashes.SHA256()
        elif key_length == KeyLength.EC384:
            return hashes.SHA384()
        elif key_length == KeyLength.EC521:
            return hashes.SHA512()
    
    raise ErrKeyConfigNotCompatible


def NewCA(config: NewCertConfig, *names: str) -> Certificate:
    """Create a new CA certificate."""
    config.is_ca = True
    return new_cert(config, *names)


def new_cert(config: NewCertConfig, *names: str) -> Certificate:
    """Internal function to create a new certificate."""
    config.valid()

    if config.cert_template is None:
        raise ValueError("certificate template is required")

    # Build certificate builder
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(config.cert_template.subject)
    builder = builder.issuer_name(config.parent.cert.subject if config.parent else config.cert_template.subject)
    builder = builder.public_key(config.public_key.public)
    builder = builder.serial_number(config.cert_template.serial_number)
    from datetime import timezone
    now = datetime.now(timezone.utc)
    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(now + config.life_time)

    # Add DNS names
    dns_names = list(names) if names else []
    if hasattr(config.cert_template, 'dns_names'):
        dns_names.extend(config.cert_template.dns_names)
    
    # Apply wildcard logic
    if config.is_wildcard:
        wildcard_match_regexp = re.compile(r"^\*\.")
        final_dns_names = []
        for name in dns_names:
            final_dns_names.append(name)
            if name != "*" and not wildcard_match_regexp.match(name):
                wildcard_name = f"*.{name}"
                if wildcard_name not in final_dns_names:
                    final_dns_names.append(wildcard_name)
        dns_names = final_dns_names

    builder = builder.add_extension(
        x509.SubjectAlternativeName([x509.DNSName(name) for name in dns_names]),
        critical=False,
    )

    # Set basic constraints
    builder = builder.add_extension(
        x509.BasicConstraints(ca=config.is_ca, path_length=None),
        critical=True,
    )

    # Key usage
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=True,
            key_encipherment=True,
            data_encipherment=True,
            key_agreement=True,
            key_cert_sign=config.is_ca,
            crl_sign=config.is_ca,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )

    # Extended key usage
    builder = builder.add_extension(
        x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]),
        critical=False,
    )

    # Sign the certificate
    if config.parent is None:
        raise ValueError("parent certificate is required for signing")

    signature_algorithm = GetSignatureAlgorithm(
        config.parent.key_pair.type,
        config.parent.key_pair.length
    )

    # Ed25519 and Ed448 require algorithm=None
    if config.parent.key_pair.type == KeyType.ED25519:
        cert = builder.sign(
            private_key=config.parent.key_pair.private,
            algorithm=None,
            backend=default_backend()
        )
    else:
        cert = builder.sign(
            private_key=config.parent.key_pair.private,
            algorithm=signature_algorithm,
            backend=default_backend()
        )

    return Certificate(
        cert=cert,
        key_pair=config.public_key,
        ca_cert=config.parent.cert if config.parent else None,
        cert_pool=config.cert_pool,
        is_ca=config.is_ca,
    )


class CertTemplate:
    """Certificate template for building certificates."""
    def __init__(self, names, ips, subject, serial):
        self.dns_names = names
        self.ip_addresses = ips or []
        self.subject = subject
        self.serial_number = serial


def GetCertTemplate(names: Optional[List[str]] = None, ips: Optional[List[ipaddress.IPv4Address | ipaddress.IPv6Address]] = None) -> CertTemplate:
    """Get the base template for certification."""
    import secrets
    from datetime import timezone
    
    if names is None or len(names) == 0:
        serial = secrets.randbelow(2**63 - 1)
        names = [str(serial), "*"]
    else:
        serial = secrets.randbelow(2**63 - 1)
        names = list(names) + [str(serial)]

    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, names[0] if names else "secure-link")
    ])
    
    return CertTemplate(names, ips or [], subject, serial)


def NewDefaultCertificationConfig() -> NewCertConfig:
    """Build a new NewCertConfig with default values."""
    config = NewCertConfig()
    config.cert_template = GetCertTemplate(None, None)
    return config


def NewDefaultCertificationConfigWithDefaultTemplate(*names: str) -> NewCertConfig:
    """Build a new NewCertConfig with default template and given names."""
    config = NewDefaultCertificationConfig()
    config.cert_template = GetCertTemplate(list(names), None)
    return config


def Unmarshal(input_bytes: bytes) -> Certificate:
    """Rebuild a Certificate from marshaled bytes."""
    try:
        export = json.loads(input_bytes.decode())
    except Exception as e:
        raise ValueError(f"failed to unmarshal certificate: {e}")

    cert_der = bytes.fromhex(export["Cert"])
    cert = x509.load_der_x509_certificate(cert_der, default_backend())

    key_pair_bytes = bytes.fromhex(export["KeyPair"])
    from .keys import UnmarshalKeyPair
    key_pair = UnmarshalKeyPair(key_pair_bytes)

    cert_pool = None
    ca_cert = None
    if export.get("CACert"):
        ca_cert_der = bytes.fromhex(export["CACert"])
        ca_cert = x509.load_der_x509_certificate(ca_cert_der, default_backend())
        cert_pool = ca_cert

    # Check if certificate is CA
    is_ca = False
    try:
        basic_constraints = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.BASIC_CONSTRAINTS)
        is_ca = basic_constraints.value.ca
    except x509.ExtensionNotFound:
        pass

    return Certificate(
        cert=cert,
        key_pair=key_pair,
        ca_cert=ca_cert,
        cert_pool=cert_pool,
        is_ca=is_ca,
    )

