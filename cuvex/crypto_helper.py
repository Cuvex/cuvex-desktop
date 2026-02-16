"""
Author: Ludwing Perez: lp@t2mc.net
SEMILLA3 LLC
https://cuvex.io/
"""
import hashlib
from cuvex.classes import RawCard, PlainContent
from cuvex.utils import heap_permutation, derive_key_pbkdf2, sort_passwords_lexicographically, concatenate_hashes
from math import comb
from cuvex.exceptions import FewerPasswordsThanRequiredException, CardVersionNotSupportedException
from Cryptodome.Cipher import AES

# Decryption constants
SUBKEY_SIZE = 32  # Legacy multisign subkey size (32 bytes)
AES_GCM_HEADER_SIZE = 4  # Header size for AES-GCM (4 zero bytes)
NONCE_SIZE = 12  # Nonce size for AES-GCM (12 bytes from IV)

# Multisign constants for new PBKDF2 format
MULTISIGN_ENCRYPTED_SIZE = 32  # Encrypted master key size
MULTISIGN_SALT_SIZE = 16  # Salt for PBKDF2 per combination
MULTISIGN_IV_SIZE = 16  # IV per combination (12 nonce + 4 counter)
MULTISIGN_BLOCK_SIZE = MULTISIGN_ENCRYPTED_SIZE + MULTISIGN_SALT_SIZE + MULTISIGN_IV_SIZE  # 64 bytes total

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

    Supports two decryption modes:
    - Legacy mode: Uses permutations and alias-derived IV
    - PBKDF2 mode: Uses lexicographic ordering and PBKDF2 key derivation

    Args:
        passwords: List of password bytearrays
        card: RawCard object with encrypted payload and crypto parameters

    Returns:
        PlainContent object with decrypted data, or None if decryption fails
    """

    header = bytearray([0] * AES_GCM_HEADER_SIZE)

    if card.crypto_params.use_pbkdf2:
        # Sort passwords lexicographically by their SHA-256 hashes
        sorted_hashes = sort_passwords_lexicographically(passwords)

        # Concatenate sorted hashes and create master key hash
        concatenated = concatenate_hashes(sorted_hashes)
        # master_key_hash = bytearray(hashlib.sha256(concatenated).digest())

        # Derive final encryption key using PBKDF2
        derived_key = derive_key_pbkdf2(
            concatenated,
            card.crypto_params.salt,
            card.crypto_params.iterations
        )

        # Extract nonce from IV (first 12 bytes)
        nonce = card.crypto_params.iv[:NONCE_SIZE]
        counter = card.crypto_params.iv[NONCE_SIZE:]

        # Decrypt payload
        try:
            plain_bytes = decrypt_aes_gcm(derived_key, nonce, counter, card.payload)
            plain_data = process_plain_content(plain_bytes)
            return plain_data
        except Exception:
            return None

    else:
        # Legacy mode with permutations
        # Derive IV from card alias (MD5 hash, first 12 bytes)
        iv_legacy = hashlib.md5(card.alias_bytes).digest()[:NONCE_SIZE]

        # Try all permutations of passwords
        for permutation in heap_permutation(passwords):
            # Concatenate permutation and hash to create key
            concatenated = b''.join(permutation)
            key = hashlib.sha256(concatenated).digest()

            # Attempt decryption
            plain_data = process_plain_content(
                decrypt_aes_gcm(
                    bytearray(key),
                    bytearray(iv_legacy),
                    header,
                    card.payload
                )
            )

            if plain_data:
                return plain_data

        return None

def _decrypt_multisign_combination_pbkdf2(passwords: list, combination_data: bytes, main_nonce: bytearray, payload: bytearray, iterations: int) -> PlainContent:
    """Decrypts a single multisign combination using PBKDF2 mode.

    Args:
        passwords: List of password bytearrays
        combination_data: 64-byte block (32 encrypted + 16 salt + 16 IV)
        main_nonce: Nonce for decrypting the main payload
        payload: Encrypted payload to decrypt
        iterations: PBKDF2 iteration count

    Returns:
        PlainContent if successful, None otherwise
    """
    header = bytearray([0] * AES_GCM_HEADER_SIZE)

    # Extract components from 64-byte block
    encrypted_master = combination_data[:MULTISIGN_ENCRYPTED_SIZE]
    salt_combination = combination_data[MULTISIGN_ENCRYPTED_SIZE:MULTISIGN_ENCRYPTED_SIZE + MULTISIGN_SALT_SIZE]
    iv_combination = combination_data[MULTISIGN_ENCRYPTED_SIZE + MULTISIGN_SALT_SIZE:MULTISIGN_BLOCK_SIZE]
    nonce_combination = iv_combination[:NONCE_SIZE]

    # Sort passwords lexicographically
    sorted_hashes = sort_passwords_lexicographically(passwords)

    # Create submaster key hash
    concatenated = concatenate_hashes(sorted_hashes)
    submaster_key_hash = bytearray(hashlib.sha256(concatenated).digest())

    # Derive key using PBKDF2
    derived_key = derive_key_pbkdf2(submaster_key_hash, bytearray(salt_combination), iterations)

    try:
        # Decrypt master key
        master_key = decrypt_aes_gcm(derived_key, bytearray(nonce_combination), header, bytearray(encrypted_master))

        # Decrypt payload
        plain_bytes = decrypt_aes_gcm(master_key, main_nonce, header, payload)

        # Validate content
        return process_plain_content(plain_bytes)

    except Exception:
        return None


def _decrypt_multisign_combination_legacy(permutation: list, encrypted_subkey: bytearray, iv: bytearray, payload: bytearray) -> PlainContent:
    """Decrypts a single multisign combination using legacy mode with a specific password permutation.

    Args:
        permutation: Specific permutation of password bytearrays
        encrypted_subkey: 32-byte encrypted master key
        iv: Initialization vector (nonce)
        payload: Encrypted payload to decrypt

    Returns:
        PlainContent if successful, None otherwise
    """
    header = bytearray([0] * AES_GCM_HEADER_SIZE)

    try:
        # Create key from permutation
        concatenated = b''.join(permutation)
        key = hashlib.sha256(concatenated).digest()

        # Decrypt master key
        master_key = decrypt_aes_gcm(bytearray(key), iv, header, encrypted_subkey)

        # Decrypt payload
        plain_bytes = decrypt_aes_gcm(master_key, iv, header, payload)

        # Validate content
        return process_plain_content(plain_bytes)

    except Exception:
        return None


def decrypt_not_all_passwords_required(passwords: list, card: RawCard) -> PlainContent:
    """Decrypts a card when not all the passwords are required to decrypt (multisig M-of-N).

    Supports two decryption modes:
    - Legacy mode: 32-byte blocks with password permutations
    - PBKDF2 mode: 64-byte blocks without permutations

    Args:
        passwords: List of password bytearrays
        card: RawCard object with encrypted multisign data

    Returns:
        PlainContent object if successful, None otherwise
    """
    num_combinations = comb(card.signs.total, card.signs.required)

    if card.crypto_params.use_pbkdf2:
        # New PBKDF2 mode - deterministic password order
        # No sensitive IV to clean (uses card.crypto_params.iv directly)
        main_nonce = card.crypto_params.iv[:NONCE_SIZE]

        for index in range(num_combinations):
            # Extract 64-byte block for this combination
            offset = index * MULTISIGN_BLOCK_SIZE
            combination_data = card.multisign[offset:offset + MULTISIGN_BLOCK_SIZE]

            # Try to decrypt with this combination
            result = _decrypt_multisign_combination_pbkdf2(
                passwords,
                combination_data,
                main_nonce,
                card.payload,
                card.crypto_params.iterations
            )

            if result:
                return result

        return None

    else:
        # Legacy mode - try all permutations for each combination
        iv_legacy = bytearray(hashlib.md5(card.alias_bytes).digest()[:NONCE_SIZE])

        def _clean_iv():
            """Zerorizes the legacy IV bytearray"""
            for i in range(len(iv_legacy)):
                iv_legacy[i] = 0

        for index in range(num_combinations):
            # Extract 32-byte encrypted subkey
            encrypted_subkey = card.multisign[index * SUBKEY_SIZE:(index + 1) * SUBKEY_SIZE]

            # Try all permutations of passwords
            for permutation in heap_permutation(passwords):
                result = _decrypt_multisign_combination_legacy(
                    permutation,
                    encrypted_subkey,
                    iv_legacy,
                    card.payload
                )

                if result:
                    _clean_iv()
                    return result

        # Clean IV before returning
        _clean_iv()
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

