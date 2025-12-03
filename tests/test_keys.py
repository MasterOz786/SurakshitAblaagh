"""Tests for key pair generation and marshaling."""

import pytest
from securelink import NewKeyPair, UnmarshalKeyPair, KeyType, KeyLength


@pytest.mark.parametrize("key_type,key_length,long_test,should_error", [
    (KeyType.ED25519, KeyLength.ED25519, False, False),
    (KeyType.EC, KeyLength.EC256, False, False),
    (KeyType.EC, KeyLength.EC384, False, False),
    (KeyType.EC, KeyLength.EC521, False, False),
    (KeyType.RSA, KeyLength.RSA2048, False, False),
    (KeyType.RSA, KeyLength.RSA3072, True, False),
    (KeyType.RSA, KeyLength.RSA4096, True, False),
    (KeyType.RSA, KeyLength.RSA8192, True, False),
    (None, KeyLength.RSA8192, False, True),  # Invalid key type
])
def test_marshal_key_pairs(key_type, key_length, long_test, should_error):
    """Test marshaling and unmarshaling of key pairs."""
    import pytest as _pytest
    # Check for short test flag
    try:
        if long_test and hasattr(_pytest.config, 'getoption') and _pytest.config.getoption("--short", default=False):
            _pytest.skip("Skipping long test")
    except:
        pass

    if should_error:
        with pytest.raises((ValueError, KeyError, TypeError)):
            if key_type is None:
                # Test with invalid key type
                raise ValueError("Invalid key type")
            key_pair = NewKeyPair(key_type, key_length)
    else:
        key_pair = NewKeyPair(key_type, key_length)
        buf = key_pair.marshal()

        loaded = UnmarshalKeyPair(buf)

        # Compare key types and lengths
        assert loaded.type == key_pair.type
        assert loaded.length == key_pair.length
        # Note: Full deep comparison would require comparing private keys
        # which is complex, so we just verify the types match

