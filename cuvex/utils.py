"""
Author: Ludwing Perez: lp@t2mc.net
SEMILLA3 LLC
https://cuvex.io/
"""
import hashlib
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Hash import SHA256

# PBKDF2 constants
DEFAULT_PBKDF2_ITERATIONS = 50000
PBKDF2_KEY_LENGTH = 32  # 256 bits
SALT_LENGTH = 16  # 128 bits

def clean_bytearray(input: bytearray):
    """Zeroizes the bytearray input
    """
    if not input:
        return
    for index in range(len(input)):
        input[index] = 0

def copy_and_clean(input) -> bytearray:
    """Copies the contents of input into a new bytearray and skips any zero byte.
    """
    if not input:
        return None

    total_count = len(input)
    result = bytearray(total_count - input.count(b'\x00'))
    result_index = 0
    for index in range(total_count):
        if input[index] != 0:
            result[result_index] = input[index]
            result_index += 1
    return result


def heap_permutation(words) -> list:
    """Genereates permutations with the elements of the input param using the
    Heap algorithm.
    """
    result = []

    def generate(size):
        if size == 1:
            result.append(words[:])
            return

        for i in range(size):
            generate(size - 1)

            if size % 2 == 1:
                words[0], words[size-1] = words[size-1], words[0]
            else:
                words[i], words[size-1] = words[size-1], words[i]

    generate(len(words))
    return result

def convert_str_to_code_points(input: str) -> list:
    """Converts every char in the input string to the corresponding Unicode code
    point.
    """
    result = []
    if not input:
        return result

    return [ord(char) for char in input]


def derive_key_pbkdf2(password_hash, salt, iterations=None):
    """Derives a cryptographic key using PBKDF2-HMAC-SHA256.

    This function implements key derivation for Cuvex BIT cards with PBKDF2.
    It takes a pre-hashed password (SHA-256) and derives a final encryption key
    using the provided salt and iteration count.

    Args:
        password_hash: Pre-computed SHA-256 hash of the password (bytearray or bytes, 32 bytes)
        salt: Random salt value (bytearray or bytes, 16 bytes)
        iterations: Number of PBKDF2 iterations (default: 50000)

    Returns:
        Derived key as bytearray (32 bytes)

    Raises:
        ValueError: If password_hash or salt have invalid lengths
    """
    if iterations is None:
        iterations = DEFAULT_PBKDF2_ITERATIONS

    if len(salt) != SALT_LENGTH:
        raise ValueError(f"salt must be {SALT_LENGTH} bytes, got {len(salt)}")

    password_bytes = bytes(password_hash)
    salt_bytes = bytes(salt)

    derived_key = PBKDF2(
        password_bytes,
        salt_bytes,
        dkLen=PBKDF2_KEY_LENGTH,
        count=iterations,
        hmac_hash_module=SHA256
    )

    return bytearray(derived_key)


def sort_passwords_lexicographically(passwords_bytes):
    """Sorts password hashes in lexicographic order.

    Cuvex BIT cards use deterministic password ordering instead of permutations.
    This function converts each password to its SHA-256 hash and sorts them
    lexicographically (byte-wise comparison).

    This eliminates the need for brute-force permutation testing during decryption,
    as the device always uses passwords in the same sorted order.

    Args:
        passwords_bytes: List of password bytearrays

    Returns:
        List of SHA-256 hashes sorted lexicographically (list of bytearrays)

    Example:
        passwords = [bytearray(b'zebra'), bytearray(b'alpha'), bytearray(b'micro')]
        sorted_hashes = sort_passwords_lexicographically(passwords)
        # Returns hashes sorted by their byte values (alpha < micro < zebra hashes)
    """
    if not passwords_bytes:
        return []

    password_hashes = []
    for pwd in passwords_bytes:
        hash_sha256 = hashlib.sha256(bytes(pwd)).digest()
        password_hashes.append(hash_sha256)

    password_hashes.sort()

    return [bytearray(h) for h in password_hashes]


def concatenate_hashes(sorted_hashes):
    """Concatenates a list of sorted password hashes.

    This is used to create a master key from multiple password hashes
    in multisig scenarios.

    Args:
        sorted_hashes: List of SHA-256 hashes (bytearrays or bytes)

    Returns:
        Concatenated bytes

    Example:
        hashes = [bytearray(32), bytearray(32)]
        result = concatenate_hashes(hashes)
        # Returns 64-byte concatenation
    """
    return b''.join(bytes(h) for h in sorted_hashes)
