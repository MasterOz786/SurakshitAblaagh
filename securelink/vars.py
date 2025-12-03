"""Constants and default values for the securelink package."""

from datetime import timedelta

# Default certificate lifetime: 3 months
DefaultCertLifeTime = timedelta(days=90)

# Service name size for hashing
serviceNameSize = 8

# Error definitions
class ErrKeyConfigNotCompatible(Exception):
    """Raised when key type and key size are not compatible."""
    pass


# Default key type and length - imported lazily to avoid circular imports
def get_default_key_type():
    """Get default key type."""
    from .keys import KeyType
    return KeyType.EC


def get_default_key_length():
    """Get default key length."""
    from .keys import KeyLength
    return KeyLength.EC256


# Lazy-loaded defaults - call functions to get values
# These are functions to avoid circular imports
DefaultKeyType = get_default_key_type
DefaultKeyLength = get_default_key_length

