"""
Author: Ludwing Perez: lp@t2mc.net
SEMILLA3 LLC
https://cuvex.io/
"""
from cuvex.utils import clean_bytearray
import cuvex.plaintext as pt

class Version:
    def __init__(self, version: str, major: int, minor: int, patch: int, other: str):
        self.full_version = version
        self.major = major
        self.minor = minor
        self.patch = patch
        self.other = other

class KeysDescriptor:
    def __init__(self, total: int, required: int):
        self.total = total
        self.required = required

class CryptoParams:
    """Cryptographic parameters for card decryption.

    These parameters are extracted from Record 3 and determine
    the decryption strategy (legacy vs PBKDF2-based).

    Attributes:
        use_pbkdf2: Whether to use PBKDF2 key derivation
        use_permutations: Whether to try password permutations
        has_biometry: Whether card requires biometric authentication (BIT1)
        salt: Salt for PBKDF2 (16 bytes, None for legacy)
        iv: Initialization Vector (16 bytes: 12 nonce + 4 counter, None for legacy)
        iterations: PBKDF2 iteration count (default 50000)
    """
    DEFAULT_PBKDF2_ITERATIONS = 50000

    def __init__(self):
        self.use_pbkdf2 = False
        self.use_permutations = True
        self.has_biometry = False
        self.salt = None
        self.iv = None
        self.iterations = self.DEFAULT_PBKDF2_ITERATIONS

    def reset_content(self):
        """Zerorizes sensitive cryptographic parameters."""
        if self.salt:
            clean_bytearray(self.salt)
            self.salt = None
        if self.iv:
            clean_bytearray(self.iv)
            self.iv = None

class RawCard:
    def __init__(self, hash: str, alias: bytearray, payload: bytearray, version: Version,
                 signs: KeysDescriptor, multisign: bytearray, crypto_params=None):
        self.card_hash = hash
        self._alias = alias
        self.payload = payload
        self.version = version
        self.signs = signs
        self.multisign = multisign
        self.crypto_params = crypto_params if crypto_params else CryptoParams()

    def reset_content(self):
        """For security reasons it is recommended to zerorize the variables
        with sensitive data.
        """
        self.card_hash = None
        clean_bytearray(self._alias)
        self._alias = None
        clean_bytearray(self.payload)
        self.payload = None
        self.version = None
        self.signs = None
        clean_bytearray(self.multisign)
        self.multisign = None
        if self.crypto_params:
            self.crypto_params.reset_content()
            self.crypto_params = None

    @property
    def alias_bytes(self):
        return self._alias

    @property
    def alias_str(self):
        result = ''
        if not self._alias:
            return result

        for code_point in self._alias:
            if code_point == 0:
                continue
            elif code_point == 182: # '¶' (182)
                result += '€'
            else:
                result += chr(code_point)

        return result

class PlainContent:
    BIP_39 = '[bip39]'
    PLAINTEXT = '[plain-text]'
    PLAINTEXT_APP = '{plain-text}'
    BIP_39_APP = '{bip39}'
    SLIP_39 = '[slip39]'
    XMR = '[xmr]'
    NOT_DEFINED = 'NOT-DEFINED'

    def __init__(self, content_type: str, content: bytearray):
        self._content = content
        self.content_type = content_type

    def reset_content(self):
        """For security reasons it is recommended to zerorize the variables
        with sensitive data.
        """
        self.content_type = None
        clean_bytearray(self._content)
        self._content = None

    @property
    def content(self):
        if self.content_type == self.BIP_39:
            return pt.process_seed_phrase(self._content, len(self.BIP_39))
        elif self.content_type == self.BIP_39_APP:
            return pt.process_full_bip_39(self._content, len(self.BIP_39_APP))
        elif self.content_type == self.PLAINTEXT:
            return pt.process_plain_text(self._content, len(self.PLAINTEXT))
        elif self.content_type == self.PLAINTEXT_APP:
            return pt.process_plain_text(self._content, len(self.PLAINTEXT_APP))
        elif self.content_type == self.SLIP_39:
            return pt.process_seed_phrase(self._content, len(self.SLIP_39))
        elif self.content_type == self.XMR:
            return pt.process_seed_phrase(self._content, len(self.XMR))
        return ''
    
    @property
    def raw_content(self):
        return self._content