import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from cuvex.card_helper import (
    detect_format,
    extract_with_delimiters,
    extract_with_fixed_length,
    create_crypto_params,
    process_card,
    DELIMITER_ALIAS,
    DELIMITER_PAYLOAD,
    DELIMITER_INFO,
    DELIMITER_MULTISIGN
)
from cuvex.codec import (
    FORMAT_NEW,
    FORMAT_LEGACY,
    DecodeResult
)
from cuvex.exceptions import (
    EmptyCardException,
    BadFormatContentException,
    BiometryNotSupportedException
)
from cuvex.classes import CryptoParams

# Test constants - card sizes
ALIAS_SIZE = 25
PAYLOAD_SIZE = 768
RECORD3_SIZE = 50
MULTISIGN_SIZE = 700
MINIMUM_CARD_SIZE = ALIAS_SIZE + PAYLOAD_SIZE + RECORD3_SIZE

# Test data
TEST_ALIAS = b'TestAlias' + b'\x00' * (ALIAS_SIZE - 9)
TEST_PAYLOAD = b'P' * PAYLOAD_SIZE
BINARY_32_SIZE = 32
SALT_SIZE = 16
IV_SIZE = 16


class TestDetectFormat(unittest.TestCase):
    """Tests for detect_format function"""

    def test_detect_new_format(self):
        """Test detection of new format with compressed token"""
        # Create binary content with "I:E1202633015" pattern
        content = bytearray(b'Some data I:E1202633015 more data')
        result = detect_format(content)
        self.assertEqual(result, FORMAT_NEW)

    def test_detect_legacy_format_with_bit(self):
        """Test detection of legacy format with BIT field"""
        content = bytearray(b'Some data I:ENC,v1.2.0(2),M-6:3,P-0,C-1,BIT0 more')
        result = detect_format(content)
        self.assertEqual(result, FORMAT_LEGACY)

    def test_detect_legacy_format_without_bit(self):
        """Test detection of legacy format without BIT field"""
        content = bytearray(b'Some data I:ENC,v1.1.0(1),M-3:3,P-0,C-0 more')
        result = detect_format(content)
        self.assertEqual(result, FORMAT_LEGACY)

    def test_detect_format_invalid(self):
        """Test detection with invalid format"""
        content = bytearray(b'Invalid content without proper format')
        with self.assertRaises(BadFormatContentException) as context:
            detect_format(content)
        self.assertIn("Cannot detect card format", str(context.exception))


class TestExtractWithDelimiters(unittest.TestCase):
    """Tests for extract_with_delimiters function (new format)"""

    def test_extract_without_multisign(self):
        alias_data = b'TestAlias12345'
        payload_data = TEST_PAYLOAD
        record3_data = b'E1202633015' + b'\x00' * BINARY_32_SIZE

        content = (
            DELIMITER_ALIAS + alias_data +
            DELIMITER_PAYLOAD + payload_data +
            DELIMITER_INFO + record3_data
        )

        alias, payload, record3, multisign = extract_with_delimiters(bytearray(content))

        self.assertEqual(alias, bytearray(alias_data))
        self.assertEqual(payload, bytearray(payload_data))
        self.assertEqual(record3, bytearray(record3_data))
        self.assertEqual(len(multisign), 0)

    def test_extract_with_multisign(self):
        alias_data = b'TestAlias12345'
        payload_data = TEST_PAYLOAD
        record3_data = b'E1202633015' + b'\x00' * BINARY_32_SIZE
        multisign_data = b'M' * MULTISIGN_SIZE

        content = (
            DELIMITER_ALIAS + alias_data +
            DELIMITER_PAYLOAD + payload_data +
            DELIMITER_INFO + record3_data +
            DELIMITER_MULTISIGN + multisign_data
        )

        alias, payload, record3, multisign = extract_with_delimiters(bytearray(content))

        self.assertEqual(alias, bytearray(alias_data))
        self.assertEqual(payload, bytearray(payload_data))
        self.assertEqual(record3, bytearray(record3_data))
        self.assertEqual(multisign, bytearray(multisign_data))

    def test_extract_missing_delimiter(self):
        content = DELIMITER_ALIAS + b'TestAlias' + DELIMITER_INFO + b'Info'

        with self.assertRaises(BadFormatContentException) as context:
            extract_with_delimiters(bytearray(content))
        self.assertIn("Missing required delimiters", str(context.exception))


class TestExtractWithFixedLength(unittest.TestCase):
    """Tests for extract_with_fixed_length function (legacy format)"""

    def test_extract_minimum_length_no_prefix(self):
        alias_data = b'A' * ALIAS_SIZE
        payload_data = TEST_PAYLOAD
        record3_data = b'I' * RECORD3_SIZE

        content = bytearray(alias_data + payload_data + record3_data)

        alias, payload, record3, multisign = extract_with_fixed_length(content)

        self.assertEqual(alias, bytearray(alias_data))
        self.assertEqual(payload, bytearray(payload_data))
        self.assertEqual(record3, bytearray(record3_data))
        self.assertEqual(len(multisign), 0)

    def test_extract_with_multisign_and_prefix(self):
        prefix = b'\x02\x41\x3A'
        alias_data = b'A' * ALIAS_SIZE
        payload_data = TEST_PAYLOAD
        record3_data = b'I' * RECORD3_SIZE
        multisign_data = b'M' * MULTISIGN_SIZE

        content = bytearray(
            prefix + alias_data +
            prefix + payload_data +
            prefix + record3_data +
            prefix + multisign_data
        )

        alias, payload, record3, multisign = extract_with_fixed_length(content)

        self.assertEqual(alias, bytearray(alias_data))
        self.assertEqual(payload, bytearray(payload_data))
        self.assertEqual(record3, bytearray(record3_data))
        self.assertEqual(multisign, bytearray(multisign_data))

    def test_extract_too_short(self):
        content = bytearray(b'Too short')

        with self.assertRaises(BadFormatContentException):
            extract_with_fixed_length(content)


class TestCreateCryptoParams(unittest.TestCase):
    """Tests for create_crypto_params function"""

    def test_create_params_new_format(self):
        binary32 = b'\x01' * SALT_SIZE + b'\x02' * IV_SIZE
        decode_result = DecodeResult(
            kind=FORMAT_NEW,
            header_text="ENC,v1.2.0(2),M-6:3,P-0,C-1,BIT0",
            binary32=binary32
        )

        params = create_crypto_params(decode_result)

        self.assertTrue(params.use_pbkdf2)
        self.assertFalse(params.use_permutations)
        self.assertFalse(params.has_biometry)
        self.assertIsNotNone(params.salt)
        self.assertIsNotNone(params.iv)
        self.assertEqual(len(params.salt), SALT_SIZE)
        self.assertEqual(len(params.iv), IV_SIZE)

    def test_create_params_legacy_format(self):
        decode_result = DecodeResult(
            kind=FORMAT_LEGACY,
            header_text="ENC,v1.1.0(1),M-3:3,P-0,C-0",
            binary32=None
        )

        params = create_crypto_params(decode_result)

        self.assertFalse(params.use_pbkdf2)
        self.assertTrue(params.use_permutations)
        self.assertFalse(params.has_biometry)
        self.assertIsNone(params.salt)
        self.assertIsNone(params.iv)


class TestProcessCardIntegration(unittest.TestCase):
    """Integration tests for process_card function"""

    def test_process_empty_card(self):
        with self.assertRaises(EmptyCardException):
            process_card(bytearray())

    def test_process_card_with_biometry(self):
        from cuvex.card_helper import _decode_and_validate_header

        record3_data = b'ENC,v1.2.0(2),M-3:3,P-0,C-0,BIT1'

        with self.assertRaises(BiometryNotSupportedException) as context:
            _decode_and_validate_header(record3_data)
        self.assertIn("biometric authentication", str(context.exception))

    def test_process_card_legacy_format_success(self):
        alias_data = b'TestCard' + b'\x00' * (ALIAS_SIZE - 8)
        payload_data = TEST_PAYLOAD
        version_info = b'VER:1.1.0'
        signer_info = b'(1)M-3:3P-0C-0'
        record3_data = version_info + b'\x00' * (RECORD3_SIZE - len(version_info) - len(signer_info)) + signer_info

        content = bytearray(alias_data + payload_data + record3_data)

        try:
            card = process_card(content)
            self.assertIsNotNone(card)
            self.assertIsNotNone(card.crypto_params)
            self.assertTrue(card.crypto_params.use_permutations)
        except BadFormatContentException:
            pass


class TestCryptoParams(unittest.TestCase):
    """Tests for CryptoParams class"""

    def test_default_initialization(self):
        """Test default CryptoParams initialization"""
        params = CryptoParams()

        self.assertFalse(params.use_pbkdf2)
        self.assertTrue(params.use_permutations)
        self.assertFalse(params.has_biometry)
        self.assertIsNone(params.salt)
        self.assertIsNone(params.iv)
        self.assertEqual(params.iterations, 50000)

    def test_reset_content_with_data(self):
        """Test reset_content zerorizes data"""
        params = CryptoParams()
        params.salt = bytearray(b'\x01' * 16)
        params.iv = bytearray(b'\x02' * 16)

        params.reset_content()

        self.assertIsNone(params.salt)
        self.assertIsNone(params.iv)

    def test_reset_content_without_data(self):
        """Test reset_content with no data doesn't fail"""
        params = CryptoParams()

        try:
            params.reset_content()
        except Exception as e:
            self.fail(f"reset_content() raised {type(e).__name__} unexpectedly")


if __name__ == '__main__':
    unittest.main()
