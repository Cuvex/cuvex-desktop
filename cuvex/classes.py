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

class RawCard:
    def __init__(self, hash: str, alias: bytearray, payload: bytearray, version: Version, 
                 signs: KeysDescriptor, multisign: bytearray):
        self.card_hash = hash
        self._alias = alias
        self.payload = payload
        self.version = version
        self.signs = signs
        self.multisign = multisign

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