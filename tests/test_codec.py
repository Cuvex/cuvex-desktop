import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from cuvex.codec import (
    _calculate_checksum,
    _validate_field_ranges,
    _extract_token_digits,
    _reconstruct_header,
    decode_new_payload,
    decode_legacy_header,
    decode_record3_payload,
    extract_salt_from_binary,
    extract_iv_from_binary,
    TokenFields,
    CodecError,
    FORMAT_NEW,
    FORMAT_LEGACY,
    TOKEN_LEN,
    NEW_TOTAL_LEN,
    SALT_LEN,
    IV_LEN,
    TOKEN_PREFIX_BYTE
)

# Test constants - valid token values
VALID_FW_MAJOR = 1
VALID_FW_MINOR = 2
VALID_FW_PATCH = 0
VALID_HW_VERSION = 2
VALID_MX = 6
VALID_MY = 3
VALID_P = 0
VALID_C = 1
VALID_BIT = 0
VALID_CHECKSUM = 5  # Sum: 1+2+0+2+6+3+0+1+0 = 15, 15 % 10 = 5

# Valid token with correct checksum
VALID_TOKEN = b'E1202630105'
VALID_HEADER = "ENC,v1.2.0(2),M-6:3,P-0,C-1,BIT0"

# Binary data sizes
BINARY_DATA_SIZE = 32


class TestCalculateChecksum(unittest.TestCase):
    """Tests for _calculate_checksum function"""

    def test_checksum_calculation(self):
        result = _calculate_checksum(VALID_FW_MAJOR, VALID_FW_MINOR, VALID_FW_PATCH,
                                     VALID_HW_VERSION, VALID_MX, VALID_MY,
                                     VALID_P, VALID_C, VALID_BIT)
        self.assertEqual(result, VALID_CHECKSUM)

    def test_checksum_all_zeros(self):
        result = _calculate_checksum(0, 0, 0, 1, 1, 1, 0, 0, 0)
        self.assertEqual(result, 3)

    def test_checksum_max_values(self):
        result = _calculate_checksum(9, 9, 9, 9, 6, 6, 1, 1, 1)
        self.assertEqual(result, 1)


class TestValidateFieldRanges(unittest.TestCase):
    """Tests for _validate_field_ranges function"""

    def test_valid_fields(self):
        try:
            _validate_field_ranges(VALID_FW_MAJOR, VALID_FW_MINOR, VALID_FW_PATCH,
                                  VALID_HW_VERSION, 3, 3, VALID_P, VALID_C, VALID_BIT)
        except CodecError:
            self.fail("_validate_field_ranges raised CodecError unexpectedly")

    def test_invalid_fw_major(self):
        with self.assertRaises(CodecError) as context:
            _validate_field_ranges(10, VALID_FW_MINOR, VALID_FW_PATCH,
                                  VALID_HW_VERSION, 3, 3, VALID_P, VALID_C, VALID_BIT)
        self.assertIn("Firmware version out of range", str(context.exception))

    def test_invalid_hw_version_too_low(self):
        with self.assertRaises(CodecError) as context:
            _validate_field_ranges(VALID_FW_MAJOR, VALID_FW_MINOR, VALID_FW_PATCH,
                                  0, 3, 3, VALID_P, VALID_C, VALID_BIT)
        self.assertIn("Hardware version out of range", str(context.exception))

    def test_invalid_hw_version_too_high(self):
        with self.assertRaises(CodecError) as context:
            _validate_field_ranges(VALID_FW_MAJOR, VALID_FW_MINOR, VALID_FW_PATCH,
                                  10, 3, 3, VALID_P, VALID_C, VALID_BIT)
        self.assertIn("Hardware version out of range", str(context.exception))

    def test_invalid_multisign_x_too_low(self):
        with self.assertRaises(CodecError) as context:
            _validate_field_ranges(VALID_FW_MAJOR, VALID_FW_MINOR, VALID_FW_PATCH,
                                  VALID_HW_VERSION, 0, 3, VALID_P, VALID_C, VALID_BIT)
        self.assertIn("Multisign values out of range", str(context.exception))

    def test_invalid_multisign_y_too_high(self):
        with self.assertRaises(CodecError) as context:
            _validate_field_ranges(VALID_FW_MAJOR, VALID_FW_MINOR, VALID_FW_PATCH,
                                  VALID_HW_VERSION, 3, 7, VALID_P, VALID_C, VALID_BIT)
        self.assertIn("Multisign values out of range", str(context.exception))

    def test_invalid_flag_p(self):
        with self.assertRaises(CodecError) as context:
            _validate_field_ranges(VALID_FW_MAJOR, VALID_FW_MINOR, VALID_FW_PATCH,
                                  VALID_HW_VERSION, 3, 3, 2, VALID_C, VALID_BIT)
        self.assertIn("Flag values out of range", str(context.exception))

    def test_invalid_flag_bit(self):
        with self.assertRaises(CodecError) as context:
            _validate_field_ranges(VALID_FW_MAJOR, VALID_FW_MINOR, VALID_FW_PATCH,
                                  VALID_HW_VERSION, 3, 3, VALID_P, VALID_C, 5)
        self.assertIn("Flag values out of range", str(context.exception))


class TestExtractTokenDigits(unittest.TestCase):
    """Tests for _extract_token_digits function"""

    def test_valid_token(self):
        """Test extraction of digits from valid token"""
        token = b'E1202633010'
        digits = _extract_token_digits(token)
        self.assertEqual(digits, [1, 2, 0, 2, 6, 3, 3, 0, 1, 0])

    def test_invalid_prefix(self):
        """Test with invalid prefix"""
        token = b'X1202633010'
        with self.assertRaises(CodecError) as context:
            _extract_token_digits(token)
        self.assertIn("Token must start with 'E'", str(context.exception))

    def test_non_digit_characters(self):
        """Test with non-digit characters"""
        token = b'E120263A010'
        with self.assertRaises(CodecError) as context:
            _extract_token_digits(token)
        self.assertIn("non-digit characters", str(context.exception))


class TestReconstructHeader(unittest.TestCase):
    """Tests for _reconstruct_header function"""

    def test_basic_reconstruction(self):
        result = _reconstruct_header(VALID_FW_MAJOR, VALID_FW_MINOR, VALID_FW_PATCH,
                                    VALID_HW_VERSION, VALID_MX, VALID_MY,
                                    VALID_P, VALID_C, VALID_BIT)
        self.assertEqual(result, VALID_HEADER)

    def test_reconstruction_with_bit1(self):
        result = _reconstruct_header(1, 2, 3, 5, 4, 2, 1, 0, 1)
        expected = "ENC,v1.2.3(5),M-4:2,P-1,C-0,BIT1"
        self.assertEqual(result, expected)


class TestTokenFields(unittest.TestCase):
    """Tests for TokenFields class"""

    def test_from_digits_valid(self):
        digits = [VALID_FW_MAJOR, VALID_FW_MINOR, VALID_FW_PATCH, VALID_HW_VERSION,
                 VALID_MX, VALID_MY, VALID_P, VALID_C, VALID_BIT, VALID_CHECKSUM]
        fields = TokenFields.from_digits(digits)

        self.assertEqual(fields.fw_major, VALID_FW_MAJOR)
        self.assertEqual(fields.fw_minor, VALID_FW_MINOR)
        self.assertEqual(fields.fw_patch, VALID_FW_PATCH)
        self.assertEqual(fields.hw_version, VALID_HW_VERSION)
        self.assertEqual(fields.mx, VALID_MX)
        self.assertEqual(fields.my, VALID_MY)
        self.assertEqual(fields.p, VALID_P)
        self.assertEqual(fields.c, VALID_C)
        self.assertEqual(fields.bit, VALID_BIT)
        self.assertEqual(fields.checksum, VALID_CHECKSUM)

    def test_from_digits_invalid_count(self):
        digits = [VALID_FW_MAJOR, VALID_FW_MINOR, VALID_FW_PATCH, VALID_HW_VERSION,
                 VALID_MX, VALID_MY, VALID_P, VALID_C, VALID_BIT]
        with self.assertRaises(CodecError) as context:
            TokenFields.from_digits(digits)
        self.assertIn("Expected 10 digits", str(context.exception))

    def test_validate_success(self):
        fields = TokenFields(VALID_FW_MAJOR, VALID_FW_MINOR, VALID_FW_PATCH,
                           VALID_HW_VERSION, VALID_MX, VALID_MY,
                           VALID_P, VALID_C, VALID_BIT, VALID_CHECKSUM)
        try:
            fields.validate()
        except CodecError:
            self.fail("validate() raised CodecError unexpectedly")

    def test_validate_checksum_mismatch(self):
        fields = TokenFields(VALID_FW_MAJOR, VALID_FW_MINOR, VALID_FW_PATCH,
                           VALID_HW_VERSION, VALID_MX, VALID_MY,
                           VALID_P, VALID_C, VALID_BIT, 9)
        with self.assertRaises(CodecError) as context:
            fields.validate()
        self.assertIn("Checksum mismatch", str(context.exception))

    def test_validate_out_of_range(self):
        fields = TokenFields(VALID_FW_MAJOR, VALID_FW_MINOR, VALID_FW_PATCH,
                           10, VALID_MX, VALID_MY, VALID_P, VALID_C, VALID_BIT, 0)
        with self.assertRaises(CodecError):
            fields.validate()

    def test_to_header(self):
        fields = TokenFields(VALID_FW_MAJOR, VALID_FW_MINOR, VALID_FW_PATCH,
                           VALID_HW_VERSION, VALID_MX, VALID_MY,
                           VALID_P, VALID_C, VALID_BIT, VALID_CHECKSUM)
        result = fields.to_header()
        self.assertEqual(result, VALID_HEADER)


class TestDecodeNewPayload(unittest.TestCase):
    """Tests for decode_new_payload function"""

    def test_valid_new_payload(self):
        binary_data = b'\x00' * BINARY_DATA_SIZE
        payload = VALID_TOKEN + binary_data

        result = decode_new_payload(payload)

        self.assertEqual(result.kind, FORMAT_NEW)
        self.assertEqual(result.header_text, VALID_HEADER)
        self.assertIsNotNone(result.binary32)
        self.assertEqual(len(result.binary32), BINARY_DATA_SIZE)

    def test_invalid_payload_length(self):
        payload = b'E1202633010' + b'\x00' * 20
        with self.assertRaises(CodecError) as context:
            decode_new_payload(payload)
        self.assertIn(f"must be exactly {NEW_TOTAL_LEN} bytes", str(context.exception))

    def test_invalid_checksum(self):
        token = b'E1202633016'
        binary_data = b'\x00' * BINARY_DATA_SIZE
        payload = token + binary_data

        with self.assertRaises(CodecError) as context:
            decode_new_payload(payload)
        self.assertTrue(
            "Checksum mismatch" in str(context.exception) or
            "Flag values out of range" in str(context.exception)
        )


class TestDecodeLegacyHeader(unittest.TestCase):
    """Tests for decode_legacy_header function"""

    def test_legacy_with_bit0(self):
        header = VALID_HEADER.encode('ascii')
        result = decode_legacy_header(header)

        self.assertEqual(result.kind, FORMAT_LEGACY)
        self.assertEqual(result.header_text, VALID_HEADER)
        self.assertIsNone(result.binary32)

    def test_legacy_with_bit1(self):
        header = b'ENC,v1.1.0(1),M-3:3,P-0,C-0,BIT1'
        result = decode_legacy_header(header)

        self.assertEqual(result.kind, FORMAT_LEGACY)
        self.assertEqual(result.header_text, 'ENC,v1.1.0(1),M-3:3,P-0,C-0,BIT1')
        self.assertIsNone(result.binary32)

    def test_legacy_without_bit(self):
        header = b'ENC,v1.1.0(1),M-3:3,P-0,C-0'
        result = decode_legacy_header(header)

        self.assertEqual(result.kind, FORMAT_LEGACY)
        self.assertEqual(result.header_text, 'ENC,v1.1.0(1),M-3:3,P-0,C-0')
        self.assertIsNone(result.binary32)

    def test_legacy_with_dev_version(self):
        header = b'ENC,v1.1.0_dev2(1),M-6:3,P-0,C-0'
        result = decode_legacy_header(header)

        self.assertEqual(result.kind, FORMAT_LEGACY)
        self.assertIsNone(result.binary32)

    def test_invalid_non_ascii(self):
        header = b'ENC,v1.2.0(2),M-6:3,P-0,C-1,\xc3\xb1'
        with self.assertRaises(CodecError) as context:
            decode_legacy_header(header)
        self.assertIn("must be valid ASCII", str(context.exception))

    def test_invalid_format(self):
        header = b'INVALID,v1.2.0(2),M-6:3,P-0,C-1'
        with self.assertRaises(CodecError) as context:
            decode_legacy_header(header)
        self.assertIn("format not recognized", str(context.exception))


class TestDecodeRecord3Payload(unittest.TestCase):
    """Tests for decode_record3_payload function (auto-detection)"""

    def test_autodetect_new_format(self):
        binary_data = b'\x00' * BINARY_DATA_SIZE
        payload = VALID_TOKEN + binary_data

        result = decode_record3_payload(payload)

        self.assertEqual(result.kind, FORMAT_NEW)
        self.assertIsNotNone(result.binary32)

    def test_autodetect_legacy_format(self):
        header = VALID_HEADER.encode('ascii')

        result = decode_record3_payload(header)

        self.assertEqual(result.kind, FORMAT_LEGACY)
        self.assertIsNone(result.binary32)

    def test_autodetect_wrong_length_new_format(self):
        payload = b'X' + b'0' * 42

        with self.assertRaises(CodecError):
            decode_record3_payload(payload)


class TestExtractBinaryComponents(unittest.TestCase):
    """Tests for extract_salt_from_binary and extract_iv_from_binary"""

    def test_extract_salt(self):
        salt_data = b'\x01' * SALT_LEN
        iv_data = b'\x02' * IV_LEN
        binary32 = salt_data + iv_data

        result = extract_salt_from_binary(binary32)

        self.assertEqual(result, salt_data)
        self.assertEqual(len(result), SALT_LEN)

    def test_extract_iv(self):
        salt_data = b'\x01' * SALT_LEN
        iv_data = b'\x02' * IV_LEN
        binary32 = salt_data + iv_data

        result = extract_iv_from_binary(binary32)

        self.assertEqual(result, iv_data)
        self.assertEqual(len(result), IV_LEN)


if __name__ == '__main__':
    unittest.main()
