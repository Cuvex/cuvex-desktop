"""
Author: Ludwing Perez: lp@t2mc.net
SEMILLA3 LLC
https://cuvex.io/
"""

class FewerPasswordsThanRequiredException(Exception):
    pass

class EmptyCardException(Exception):
    pass

class BadFormatContentException(Exception):
    pass

class CardVersionNotSupportedException(Exception):
    pass

class BiometryNotSupportedException(Exception):
    """Raised when a card requires biometric authentication (BIT1).

    Desktop application cannot decrypt cards with biometry enabled.
    Only cards with BIT0 (no biometry) can be decrypted.
    """
    pass