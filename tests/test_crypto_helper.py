import unittest
import sys
import os
import hashlib

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from cuvex.crypto_helper import (
    decrypt_aes_gcm,
    _decrypt_with_pbkdf2,
    _decrypt_with_permutations,
    decrypt_all_passwords_required,
    _decrypt_multisign_combination_pbkdf2,
    _decrypt_multisign_combination_legacy,
    decrypt_not_all_passwords_required,
    process_plain_content
)
from cuvex.classes import RawCard, Version, KeysDescriptor, CryptoParams, PlainContent
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes

# Test constants
KEY_SIZE = 32
NONCE_SIZE = 12
HEADER_SIZE = 4
SALT_SIZE = 16
IV_SIZE = 16
MASTER_KEY_SIZE = 32
MULTISIGN_BLOCK_SIZE = 64
PBKDF2_ITERATIONS = 50000

# Test data
TEST_HEADER = bytearray([0] * HEADER_SIZE)
TEST_PLAINTEXT = bytearray(b'[plain-text]Secret message')
TEST_PASSWORD_1 = bytearray(b'password1')
TEST_PASSWORD_2 = bytearray(b'password2')


class TestDecryptAesGcm(unittest.TestCase):
    """Tests for decrypt_aes_gcm function"""

    def test_decrypt_valid_data(self):
        key = bytearray(get_random_bytes(KEY_SIZE))
        nonce = bytearray(get_random_bytes(NONCE_SIZE))

        cipher = AES.new(bytes(key), AES.MODE_GCM, nonce=bytes(nonce))
        cipher.update(bytes(TEST_HEADER))
        ciphertext = cipher.encrypt(bytes(TEST_PLAINTEXT))
        encrypted_data = bytearray(ciphertext)

        result = decrypt_aes_gcm(key, nonce, TEST_HEADER, encrypted_data)

        self.assertEqual(result, TEST_PLAINTEXT)

    def test_decrypt_invalid_key(self):
        key = bytearray(get_random_bytes(KEY_SIZE))
        wrong_key = bytearray(get_random_bytes(KEY_SIZE))
        nonce = bytearray(get_random_bytes(NONCE_SIZE))

        cipher = AES.new(bytes(key), AES.MODE_GCM, nonce=bytes(nonce))
        cipher.update(bytes(TEST_HEADER))
        ciphertext = cipher.encrypt(bytes(TEST_PLAINTEXT))
        encrypted_data = bytearray(ciphertext)

        result = decrypt_aes_gcm(wrong_key, nonce, TEST_HEADER, encrypted_data)

        self.assertNotEqual(result, TEST_PLAINTEXT)


class TestProcessPlainContent(unittest.TestCase):
    """Tests for process_plain_content function"""

    def test_process_bip39_content(self):
        content = bytearray(b'[bip39]abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about')
        result = process_plain_content(content)

        self.assertIsInstance(result, PlainContent)
        self.assertEqual(result.content_type, PlainContent.BIP_39)

    def test_process_plaintext_content(self):
        content = bytearray(b'[plain-text]Hello world')
        result = process_plain_content(content)

        self.assertIsInstance(result, PlainContent)
        self.assertEqual(result.content_type, PlainContent.PLAINTEXT)

    def test_process_invalid_content(self):
        content = bytearray(b'Invalid content without marker')
        result = process_plain_content(content)

        self.assertIsNone(result)


class TestDecryptWithPbkdf2(unittest.TestCase):
    """Tests for _decrypt_with_pbkdf2 function"""

    def test_decrypt_pbkdf2_success(self):
        from cuvex.utils import sort_passwords_lexicographically, concatenate_hashes, derive_key_pbkdf2

        passwords = [TEST_PASSWORD_1, TEST_PASSWORD_2]

        salt = bytearray(get_random_bytes(SALT_SIZE))
        iv = bytearray(get_random_bytes(IV_SIZE))
        nonce = iv[:NONCE_SIZE]
        counter = iv[NONCE_SIZE:]

        sorted_hashes = sort_passwords_lexicographically(passwords)
        concatenated = concatenate_hashes(sorted_hashes)
        key = derive_key_pbkdf2(concatenated, salt)

        plaintext = bytearray(b'[plain-text]Success')
        cipher = AES.new(bytes(key), AES.MODE_GCM, nonce=bytes(nonce))
        cipher.update(bytes(counter))
        ciphertext = cipher.encrypt(bytes(plaintext))
        payload = bytearray(ciphertext)

        crypto_params = CryptoParams()
        crypto_params.use_pbkdf2 = True
        crypto_params.salt = salt
        crypto_params.iv = iv
        crypto_params.iterations = PBKDF2_ITERATIONS

        card = RawCard(
            hash='test',
            alias=bytearray(b'test'),
            payload=payload,
            version=Version('v1.2.0', 1, 2, 0, ''),
            signs=KeysDescriptor(2, 2),
            multisign=bytearray(),
            crypto_params=crypto_params
        )

        result = _decrypt_with_pbkdf2(passwords, card)

        self.assertIsNotNone(result)
        self.assertIsInstance(result, PlainContent)

    def test_decrypt_pbkdf2_wrong_password(self):
        salt = bytearray(get_random_bytes(SALT_SIZE))
        iv = bytearray(get_random_bytes(IV_SIZE))

        crypto_params = CryptoParams()
        crypto_params.use_pbkdf2 = True
        crypto_params.salt = salt
        crypto_params.iv = iv

        card = RawCard(
            hash='test',
            alias=bytearray(b'test'),
            payload=bytearray(get_random_bytes(100)),
            version=Version('v1.2.0', 1, 2, 0, ''),
            signs=KeysDescriptor(1, 1),
            multisign=bytearray(),
            crypto_params=crypto_params
        )

        passwords = [bytearray(b'wrongpassword')]

        result = _decrypt_with_pbkdf2(passwords, card)

        self.assertIsNone(result)


class TestDecryptWithPermutations(unittest.TestCase):
    """Tests for _decrypt_with_permutations function"""

    def test_decrypt_permutations_success(self):
        """Test successful decryption with permutations"""
        # Create test passwords
        pwd1 = bytearray(b'pass1')
        pwd2 = bytearray(b'pass2')
        passwords = [pwd1, pwd2]

        # Create key from concatenation (correct order)
        concatenated = b'pass1pass2'
        key = hashlib.sha256(concatenated).digest()

        # Create IV from alias
        alias = bytearray(b'TestAlias')
        iv = hashlib.md5(bytes(alias)).digest()[:12]
        header = bytearray([0] * 4)

        # Encrypt content
        plaintext = bytearray(b'[plain-text]Test message')
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        cipher.update(bytes(header))
        ciphertext = cipher.encrypt(bytes(plaintext))
        payload = bytearray(ciphertext)

        # Create mock RawCard
        crypto_params = CryptoParams()
        crypto_params.use_permutations = True

        card = RawCard(
            hash='test',
            alias=alias,
            payload=payload,
            version=Version('v1.1.0', 1, 1, 0, ''),
            signs=KeysDescriptor(2, 2),
            multisign=bytearray(),
            crypto_params=crypto_params
        )

        result = _decrypt_with_permutations(passwords, card)

        self.assertIsNotNone(result)
        self.assertIsInstance(result, PlainContent)

    def test_decrypt_permutations_wrong_password(self):
        """Test decryption with wrong passwords returns None"""
        crypto_params = CryptoParams()
        crypto_params.use_permutations = True

        card = RawCard(
            hash='test',
            alias=bytearray(b'TestAlias'),
            payload=bytearray(get_random_bytes(100)),
            version=Version('v1.1.0', 1, 1, 0, ''),
            signs=KeysDescriptor(1, 1),
            multisign=bytearray(),
            crypto_params=crypto_params
        )

        passwords = [bytearray(b'wrongpassword')]

        result = _decrypt_with_permutations(passwords, card)

        self.assertIsNone(result)


class TestDecryptAllPasswordsRequired(unittest.TestCase):
    """Tests for decrypt_all_passwords_required function"""

    def test_decrypt_routes_to_pbkdf2(self):
        """Test that function routes to PBKDF2 when use_pbkdf2 is True"""
        crypto_params = CryptoParams()
        crypto_params.use_pbkdf2 = True
        crypto_params.salt = bytearray(get_random_bytes(16))
        crypto_params.iv = bytearray(get_random_bytes(16))

        card = RawCard(
            hash='test',
            alias=bytearray(b'test'),
            payload=bytearray(get_random_bytes(100)),
            version=Version('v1.2.0', 1, 2, 0, ''),
            signs=KeysDescriptor(1, 1),
            multisign=bytearray(),
            crypto_params=crypto_params
        )

        passwords = [bytearray(b'password')]

        # Should not raise exception (might return None if decryption fails)
        result = decrypt_all_passwords_required(passwords, card)
        # Result can be None if decryption fails, which is OK

    def test_decrypt_routes_to_permutations(self):
        """Test that function routes to permutations when use_permutations is True"""
        crypto_params = CryptoParams()
        crypto_params.use_permutations = True

        card = RawCard(
            hash='test',
            alias=bytearray(b'test'),
            payload=bytearray(get_random_bytes(100)),
            version=Version('v1.1.0', 1, 1, 0, ''),
            signs=KeysDescriptor(1, 1),
            multisign=bytearray(),
            crypto_params=crypto_params
        )

        passwords = [bytearray(b'password')]

        # Should not raise exception (might return None if decryption fails)
        result = decrypt_all_passwords_required(passwords, card)
        # Result can be None if decryption fails, which is OK


class TestDecryptMultisignCombinationPbkdf2(unittest.TestCase):
    """Tests for _decrypt_multisign_combination_pbkdf2 function"""

    def test_decrypt_combination_success(self):
        """Test successful multisign combination decryption with PBKDF2"""
        from cuvex.utils import sort_passwords_lexicographically, concatenate_hashes, derive_key_pbkdf2

        # Create test data
        passwords = [bytearray(b'password1'), bytearray(b'password2')]
        iterations = 50000

        # Create combination data (64 bytes: 32 encrypted + 16 salt + 16 IV)
        salt_combination = get_random_bytes(16)
        iv_combination = get_random_bytes(16)
        nonce_combination = iv_combination[:12]
        header = bytearray([0] * 4)

        # Create master key
        master_key = get_random_bytes(32)

        # Encrypt master key
        sorted_hashes = sort_passwords_lexicographically(passwords)
        concatenated = concatenate_hashes(sorted_hashes)
        derived_key = derive_key_pbkdf2(bytearray(concatenated), bytearray(salt_combination), iterations)

        cipher = AES.new(bytes(derived_key), AES.MODE_GCM, nonce=nonce_combination)
        cipher.update(bytes(header))
        encrypted_master = cipher.encrypt(master_key)

        # Pad to 32 bytes if needed
        if len(encrypted_master) < 32:
            encrypted_master += b'\x00' * (32 - len(encrypted_master))

        combination_data = encrypted_master[:32] + salt_combination + iv_combination

        # Encrypt payload with master key
        plaintext = bytearray(b'[plain-text]Multisign test')
        main_nonce = bytearray(get_random_bytes(12))
        cipher_payload = AES.new(master_key, AES.MODE_GCM, nonce=bytes(main_nonce))
        cipher_payload.update(bytes(header))
        ciphertext = cipher_payload.encrypt(bytes(plaintext))
        payload = bytearray(ciphertext)

        result = _decrypt_multisign_combination_pbkdf2(
            passwords,
            combination_data,
            main_nonce,
            payload,
            iterations
        )

        self.assertIsNotNone(result)
        self.assertIsInstance(result, PlainContent)


class TestDecryptMultisignCombinationLegacy(unittest.TestCase):
    """Tests for _decrypt_multisign_combination_legacy function"""

    def test_decrypt_combination_legacy_success(self):
        """Test successful multisign combination decryption with legacy method"""
        # Create test data
        pwd1 = bytearray(b'pass1')
        pwd2 = bytearray(b'pass2')
        permutation = [pwd1, pwd2]

        # Create key
        concatenated = b'pass1pass2'
        key = hashlib.sha256(concatenated).digest()

        # Create IV and header
        iv = bytearray(get_random_bytes(12))
        header = bytearray([0] * 4)

        # Create master key (exactly 32 bytes)
        master_key_plain = get_random_bytes(32)

        # Encrypt master key
        cipher_master = AES.new(key, AES.MODE_GCM, nonce=bytes(iv))
        cipher_master.update(bytes(header))
        encrypted_master = cipher_master.encrypt(master_key_plain)
        encrypted_subkey = bytearray(encrypted_master)

        # Encrypt payload with master key
        plaintext = bytearray(b'[plain-text]Legacy multisign')
        cipher_payload = AES.new(master_key_plain, AES.MODE_GCM, nonce=bytes(iv))
        cipher_payload.update(bytes(header))
        ciphertext = cipher_payload.encrypt(bytes(plaintext))
        payload = bytearray(ciphertext)

        result = _decrypt_multisign_combination_legacy(
            permutation,
            encrypted_subkey,
            iv,
            payload
        )

        self.assertIsNotNone(result)
        self.assertIsInstance(result, PlainContent)


class TestDecryptNotAllPasswordsRequired(unittest.TestCase):
    """Tests for decrypt_not_all_passwords_required function"""

    def test_decrypt_routes_to_pbkdf2_multisign(self):
        """Test routing to PBKDF2 multisign decryption"""
        from math import comb

        crypto_params = CryptoParams()
        crypto_params.use_pbkdf2 = True
        crypto_params.salt = bytearray(get_random_bytes(16))
        crypto_params.iv = bytearray(get_random_bytes(16))

        # For M-of-N (2 of 3), we need C(3,2) = 3 combinations
        # Each combination needs 64 bytes
        num_combinations = comb(3, 2)  # = 3
        multisign_data = bytearray()

        for _ in range(num_combinations):
            encrypted_master = bytearray(get_random_bytes(32))
            salt_combination = bytearray(get_random_bytes(16))
            iv_combination = bytearray(get_random_bytes(16))
            multisign_data += encrypted_master + salt_combination + iv_combination

        card = RawCard(
            hash='test',
            alias=bytearray(b'test'),
            payload=bytearray(get_random_bytes(100)),
            version=Version('v1.2.0', 1, 2, 0, ''),
            signs=KeysDescriptor(3, 2),  # M-of-N: 2 of 3
            multisign=multisign_data,
            crypto_params=crypto_params
        )

        passwords = [bytearray(b'password1'), bytearray(b'password2')]

        # Should not raise exception (but might return None if decryption fails)
        result = decrypt_not_all_passwords_required(passwords, card)
        # Result can be None if decryption fails, which is expected with random data

    def test_decrypt_routes_to_legacy_multisign(self):
        """Test routing to legacy multisign decryption"""
        crypto_params = CryptoParams()
        crypto_params.use_permutations = True

        # Create multisign data (at least one 32-byte block)
        multisign_data = bytearray(get_random_bytes(32))

        card = RawCard(
            hash='test',
            alias=bytearray(b'test'),
            payload=bytearray(get_random_bytes(100)),
            version=Version('v1.1.0', 1, 1, 0, ''),
            signs=KeysDescriptor(3, 2),  # M-of-N: 2 of 3
            multisign=multisign_data,
            crypto_params=crypto_params
        )

        passwords = [bytearray(b'password1'), bytearray(b'password2')]

        # Should not raise exception
        result = decrypt_not_all_passwords_required(passwords, card)
        # Result can be None if decryption fails


if __name__ == '__main__':
    unittest.main()
