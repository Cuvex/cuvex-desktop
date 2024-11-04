"""
Author: Ludwing Perez: lp@t2mc.net
SEMILLA3 LLC
https://cuvex.io/
"""
import hashlib
from cuvex.classes import RawCard, PlainContent
from cuvex.utils import heap_permutation
from math import comb
from cuvex.exceptions import FewerPasswordsThanRequiredException, CardVersionNotSupportedException
from Cryptodome.Cipher import AES

SUBKEY_SIZE = 32

def decrypt_aes_gcm(key: bytearray, iv: bytearray, header: bytearray, data: bytearray) -> bytearray:
    """Decrypts data using the AES algorithm in GCM mode.
    """
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    cipher.update(header)
    return bytearray(cipher.decrypt(data))

def process_plain_content(plain_content: bytearray) -> PlainContent:
    """Analyzes the type of decrypted content and formats acording to it.  
    Returns a PlainContent with the content of the formated and cleaned content.
    For security reasons the input param plain_content is zerorized and 
    SHOULD NOT BE USED after a call to this function.
    """
    if not plain_content:
        return None
    
    if plain_content.startswith(PlainContent.BIP_39.encode('utf-8')):
        return PlainContent(PlainContent.BIP_39, plain_content)
    
    elif plain_content.startswith(PlainContent.BIP_39_APP.encode('utf-8')):
        return PlainContent(PlainContent.BIP_39_APP, plain_content)
    
    elif plain_content.startswith(PlainContent.PLAINTEXT.encode('utf-8')):
        return PlainContent(PlainContent.PLAINTEXT, plain_content)
    
    elif plain_content.startswith(PlainContent.PLAINTEXT_APP.encode('utf-8')):
        return PlainContent(PlainContent.PLAINTEXT_APP, plain_content)
    
    elif plain_content.startswith(PlainContent.SLIP_39.encode('utf-8')):
        return PlainContent(PlainContent.SLIP_39, plain_content)

    elif plain_content.startswith(PlainContent.XMR.encode('utf-8')):
        return PlainContent(PlainContent.XMR, plain_content)
    
    return None

def decrypt_all_passwords_required(passwords: list, card: RawCard) -> PlainContent:
    """Decrypts a card when the required passwords to decrypt are the same as the
    total passwords used to generate the cyphered content.
    """
    for permutation in heap_permutation(passwords):
        plain_data = process_plain_content(decrypt_aes_gcm(hashlib.sha256(b''.join(permutation)).digest(), 
                                    hashlib.md5(card.alias_bytes).digest()[:12], 
                                    bytearray([0] * 4), 
                                    card.payload))
        if plain_data:
            return plain_data
    return None

def decrypt_not_all_passwords_required(passwords: list, card: RawCard) -> PlainContent:
    """Decrypts a card when not all the passwords are required to decrypt.
    """
    header = bytearray([0] * 4)
    iv = bytearray(hashlib.md5(card.alias_bytes).digest()[:12])

    def _clean():
        """Zerorizes the content of the IV bytearray
        """
        for i in range(len(iv)):
            iv[i] = 0

    for index in range(0, comb(card.signs.total, card.signs.required)):
        for permutation in heap_permutation(passwords):

            try:
                key_level_0 = decrypt_aes_gcm(
                    hashlib.sha256(b''.join(permutation)).digest(), 
                    iv, 
                    header, 
                    card.multisign[index * SUBKEY_SIZE: (index + 1) * SUBKEY_SIZE])
            except Exception as e:
                continue

            try:
                plain_bytes = decrypt_aes_gcm(key_level_0, iv, header, card.payload)
            except Exception as e:
                continue

            result = process_plain_content(plain_bytes)
            if result:
                _clean()
                return result

    _clean()
    return None

def decrypt_card(passwords_code_points: list, card: RawCard) -> PlainContent:
    """Decrypt the content of a card. Returns a PlainContent objetct with
    the plain contents of the card.

    The input param "passwords" must be a list of code points of every typed
    password insted of the password converted to UTF-8 byte array, because
    the decryption function expects as input an array of bytes where the 
    non-ascii chars are represented by their code points (between 0 and 255) and
    not the byte representation of that code point (in python could be up to
    4 bytes).
    """
    if not (card.version.major >= 1 and card.version.minor >= 1):
        raise CardVersionNotSupportedException
    if len(passwords_code_points) < card.signs.required:
        raise FewerPasswordsThanRequiredException
    
    passwords_bytes = []

    for password_code_points in passwords_code_points:
        pass_byte_array = bytearray()
        for code_point in password_code_points:
            if code_point == 8364: # € = 8364 - ¶ = 182
                pass_byte_array.append(194)
            else:
                pass_byte_array.append(code_point)
        passwords_bytes.append(pass_byte_array)

    if card.signs.total != card.signs.required:
        result = decrypt_not_all_passwords_required(passwords_bytes, card)
    else:
        result = decrypt_all_passwords_required(passwords_bytes, card)
    
    # For security reasons, the bytes used to decrypt the secret are zerorized
    for element in passwords_bytes:
        for index in range(len(element)):
            element[index] = 0
    del passwords_bytes
    return result

