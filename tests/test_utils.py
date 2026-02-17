import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from cuvex.utils import (
    derive_key_pbkdf2,
    sort_passwords_lexicographically,
    concatenate_hashes,
    clean_bytearray,
    copy_and_clean,
    heap_permutation,
    convert_str_to_code_points,
    DEFAULT_PBKDF2_ITERATIONS,
    PBKDF2_KEY_LENGTH,
    SALT_LENGTH
)

# Test constants
HASH_SIZE = 32
TEST_PASSWORD_1 = bytearray(b'\x01' * HASH_SIZE)
TEST_PASSWORD_2 = bytearray(b'\x02' * HASH_SIZE)
TEST_SALT = bytearray(b'\x02' * SALT_LENGTH)
CUSTOM_ITERATIONS = 10000


class TestDeriveKeyPbkdf2(unittest.TestCase):
    """Tests for derive_key_pbkdf2 function"""

    def test_derive_key_basic(self):
        result = derive_key_pbkdf2(TEST_PASSWORD_1, TEST_SALT)

        self.assertIsInstance(result, bytearray)
        self.assertEqual(len(result), PBKDF2_KEY_LENGTH)

    def test_derive_key_with_custom_iterations(self):
        result = derive_key_pbkdf2(TEST_PASSWORD_1, TEST_SALT, CUSTOM_ITERATIONS)

        self.assertIsInstance(result, bytearray)
        self.assertEqual(len(result), PBKDF2_KEY_LENGTH)

    def test_derive_key_default_iterations(self):
        result1 = derive_key_pbkdf2(TEST_PASSWORD_1, TEST_SALT)
        result2 = derive_key_pbkdf2(TEST_PASSWORD_1, TEST_SALT, DEFAULT_PBKDF2_ITERATIONS)

        self.assertEqual(result1, result2)

    def test_derive_key_deterministic(self):
        result1 = derive_key_pbkdf2(TEST_PASSWORD_1, TEST_SALT)
        result2 = derive_key_pbkdf2(TEST_PASSWORD_1, TEST_SALT)

        self.assertEqual(result1, result2)

    def test_derive_key_different_salts(self):
        salt1 = bytearray(b'\x02' * SALT_LENGTH)
        salt2 = bytearray(b'\x03' * SALT_LENGTH)

        result1 = derive_key_pbkdf2(TEST_PASSWORD_1, salt1)
        result2 = derive_key_pbkdf2(TEST_PASSWORD_1, salt2)

        self.assertNotEqual(result1, result2)

    def test_derive_key_different_passwords(self):
        result1 = derive_key_pbkdf2(TEST_PASSWORD_1, TEST_SALT)
        result2 = derive_key_pbkdf2(TEST_PASSWORD_2, TEST_SALT)

        self.assertNotEqual(result1, result2)

    def test_derive_key_invalid_salt_length(self):
        salt = bytearray(b'\x02' * 10)

        with self.assertRaises(ValueError) as context:
            derive_key_pbkdf2(TEST_PASSWORD_1, salt)
        self.assertIn(f"salt must be {SALT_LENGTH} bytes", str(context.exception))

    def test_derive_key_accepts_bytes(self):
        password_hash = b'\x01' * HASH_SIZE
        salt = b'\x02' * SALT_LENGTH

        result = derive_key_pbkdf2(password_hash, salt)

        self.assertIsInstance(result, bytearray)
        self.assertEqual(len(result), PBKDF2_KEY_LENGTH)


class TestSortPasswordsLexicographically(unittest.TestCase):
    """Tests for sort_passwords_lexicographically function"""

    def test_sort_basic(self):
        pwd1 = bytearray(b'zebra')
        pwd2 = bytearray(b'alpha')
        pwd3 = bytearray(b'micro')

        passwords = [pwd1, pwd2, pwd3]
        sorted_hashes = sort_passwords_lexicographically(passwords)

        self.assertEqual(len(sorted_hashes), 3)
        for hash_val in sorted_hashes:
            self.assertEqual(len(hash_val), HASH_SIZE)

        for i in range(len(sorted_hashes) - 1):
            self.assertLessEqual(sorted_hashes[i], sorted_hashes[i + 1])

    def test_sort_deterministic(self):
        pwd1 = bytearray(b'password1')
        pwd2 = bytearray(b'password2')
        pwd3 = bytearray(b'password3')

        passwords = [pwd1, pwd2, pwd3]
        result1 = sort_passwords_lexicographically(passwords)
        result2 = sort_passwords_lexicographically(passwords)

        self.assertEqual(result1, result2)

    def test_sort_single_password(self):
        passwords = [bytearray(b'single')]

        sorted_hashes = sort_passwords_lexicographically(passwords)

        self.assertEqual(len(sorted_hashes), 1)
        self.assertEqual(len(sorted_hashes[0]), HASH_SIZE)

    def test_sort_empty_list(self):
        sorted_hashes = sort_passwords_lexicographically([])

        self.assertEqual(len(sorted_hashes), 0)

    def test_sort_returns_bytearrays(self):
        passwords = [bytearray(b'pwd1'), bytearray(b'pwd2')]

        sorted_hashes = sort_passwords_lexicographically(passwords)

        for hash_val in sorted_hashes:
            self.assertIsInstance(hash_val, bytearray)

    def test_sort_order_example(self):
        pwd1 = bytearray(b'aaa')
        pwd2 = bytearray(b'zzz')

        passwords = [pwd2, pwd1]
        sorted_hashes = sort_passwords_lexicographically(passwords)

        self.assertEqual(len(sorted_hashes), 2)


class TestConcatenateHashes(unittest.TestCase):
    """Tests for concatenate_hashes function"""

    def test_concatenate_basic(self):
        result = concatenate_hashes([TEST_PASSWORD_1, TEST_PASSWORD_2])

        self.assertEqual(len(result), 2 * HASH_SIZE)
        self.assertEqual(result[:HASH_SIZE], bytes(TEST_PASSWORD_1))
        self.assertEqual(result[HASH_SIZE:], bytes(TEST_PASSWORD_2))

    def test_concatenate_single_hash(self):
        result = concatenate_hashes([TEST_PASSWORD_1])

        self.assertEqual(len(result), HASH_SIZE)
        self.assertEqual(result, bytes(TEST_PASSWORD_1))

    def test_concatenate_multiple_hashes(self):
        hash3 = bytearray(b'\x03' * HASH_SIZE)

        result = concatenate_hashes([TEST_PASSWORD_1, TEST_PASSWORD_2, hash3])

        self.assertEqual(len(result), 3 * HASH_SIZE)
        self.assertEqual(result[:HASH_SIZE], bytes(TEST_PASSWORD_1))
        self.assertEqual(result[HASH_SIZE:2*HASH_SIZE], bytes(TEST_PASSWORD_2))
        self.assertEqual(result[2*HASH_SIZE:], bytes(hash3))

    def test_concatenate_empty_list(self):
        result = concatenate_hashes([])

        self.assertEqual(len(result), 0)
        self.assertEqual(result, b'')

    def test_concatenate_accepts_bytes(self):
        hash1 = b'\x01' * HASH_SIZE
        hash2 = b'\x02' * HASH_SIZE

        result = concatenate_hashes([hash1, hash2])

        self.assertEqual(len(result), 2 * HASH_SIZE)

    def test_concatenate_preserves_order(self):
        result1 = concatenate_hashes([TEST_PASSWORD_1, TEST_PASSWORD_2])
        result2 = concatenate_hashes([TEST_PASSWORD_2, TEST_PASSWORD_1])

        self.assertNotEqual(result1, result2)


class TestCleanBytearray(unittest.TestCase):
    """Tests for clean_bytearray function (existing but worth testing)"""

    def test_clean_basic(self):
        """Test basic zerorization"""
        data = bytearray(b'\x01\x02\x03\x04')
        clean_bytearray(data)

        self.assertEqual(data, bytearray(b'\x00\x00\x00\x00'))

    def test_clean_empty(self):
        """Test cleaning empty bytearray"""
        data = bytearray()
        clean_bytearray(data)

        self.assertEqual(len(data), 0)


class TestCopyAndClean(unittest.TestCase):
    """Tests for copy_and_clean function (existing but worth testing)"""

    def test_copy_and_clean_basic(self):
        """Test copying and skipping zero bytes"""
        original = bytearray(b'\x01\x00\x03\x04')
        copy = copy_and_clean(original)

        # copy_and_clean skips zero bytes but doesn't zerorize the original
        self.assertEqual(copy, bytearray(b'\x01\x03\x04'))
        # Original is not modified
        self.assertEqual(original, bytearray(b'\x01\x00\x03\x04'))


class TestHeapPermutation(unittest.TestCase):
    """Tests for heap_permutation function (existing but worth testing)"""

    def test_permutation_basic(self):
        """Test basic permutation generation"""
        items = [bytearray(b'a'), bytearray(b'b'), bytearray(b'c')]
        permutations = list(heap_permutation(items))

        # Should generate 3! = 6 permutations
        self.assertEqual(len(permutations), 6)

    def test_permutation_single_item(self):
        """Test permutation with single item"""
        items = [bytearray(b'a')]
        permutations = list(heap_permutation(items))

        self.assertEqual(len(permutations), 1)


class TestConvertStrToCodePoints(unittest.TestCase):
    """Tests for convert_str_to_code_points function (existing but worth testing)"""

    def test_convert_basic(self):
        """Test basic string to code points conversion"""
        result = convert_str_to_code_points("abc")

        self.assertEqual(result, [97, 98, 99])

    def test_convert_empty(self):
        """Test empty string"""
        result = convert_str_to_code_points("")

        self.assertEqual(result, [])


if __name__ == '__main__':
    unittest.main()
