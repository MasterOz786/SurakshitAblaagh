"""Tests for certificate and CA management."""

import pytest
import ssl
import socket
import asyncio
from securelink import (
    NewCA,
    NewDefaultCertificationConfig,
    NewDefaultCertificationConfigWithDefaultTemplate,
    GetBaseTLSConfig,
    Unmarshal,
    KeyType,
    KeyLength,
)


@pytest.mark.parametrize("key_type,key_length,long_test,should_error", [
    (KeyType.ED25519, KeyLength.ED25519, False, False),
    (KeyType.EC, KeyLength.EC256, False, False),
    (KeyType.EC, KeyLength.EC384, False, False),
    (KeyType.EC, KeyLength.EC521, False, False),
    (KeyType.RSA, KeyLength.RSA2048, False, False),
    (KeyType.RSA, KeyLength.RSA3072, True, False),
    (KeyType.RSA, KeyLength.RSA4096, True, False),
    (KeyType.RSA, KeyLength.RSA8192, True, False),
    (KeyType.RSA, KeyLength.EC256, False, True),  # Invalid combination
])
def test_new_ca(key_type, key_length, long_test, should_error):
    """Test creating a new CA with different key types."""
    import pytest as _pytest
    try:
        if long_test and hasattr(_pytest.config, 'getoption') and _pytest.config.getoption("--short", default=False):
            pytest.skip("Skipping long test")
    except:
        pass

    conf = NewDefaultCertificationConfig()
    conf.key_type = key_type
    conf.key_length = key_length

    if should_error:
        with pytest.raises(Exception):
            ca = NewCA(conf, "ca")
    else:
        ca = NewCA(conf, "ca")
        assert ca is not None
        assert ca.is_ca is True


@pytest.mark.parametrize("key_type,key_length,long_test", [
    (KeyType.ED25519, KeyLength.ED25519, False),
    (KeyType.EC, KeyLength.EC256, False),
    (KeyType.EC, KeyLength.EC384, False),
    (KeyType.EC, KeyLength.EC521, False),
    (KeyType.RSA, KeyLength.RSA2048, False),
    (KeyType.RSA, KeyLength.RSA3072, True),
    (KeyType.RSA, KeyLength.RSA4096, True),
    (KeyType.RSA, KeyLength.RSA8192, True),
])
def test_certificate_marshaling(key_type, key_length, long_test):
    """Test marshaling and unmarshaling certificates."""
    import pytest as _pytest
    try:
        if long_test and hasattr(_pytest.config, 'getoption') and _pytest.config.getoption("--short", default=False):
            pytest.skip("Skipping long test")
    except:
        pass

    conf = NewDefaultCertificationConfig()
    ca = NewCA(conf, "ca")

    conf = NewDefaultCertificationConfig()
    cert = ca.new_cert(conf, "node1")
    assert cert is not None

    as_bytes = cert.marshal()

    cert2 = Unmarshal(as_bytes)
    assert cert2 is not None
    assert cert2.cert.serial_number == cert.cert.serial_number
    assert cert2.is_ca == cert.is_ca

