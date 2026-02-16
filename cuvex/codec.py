"""
Author: Ludwing Perez: lp@t2mc.net
SEMILLA3 LLC
https://cuvex.io/

Codec for Record 3 compression/decompression.
Supports legacy ASCII format and new compressed format with PBKDF2.
"""
import re

# Token structure constants (new format)
TOKEN_LEN = 11
TOKEN_PREFIX = 'E'
TOKEN_PREFIX_BYTE = b'E'

# Binary data constants
BIN_LEN = 32
SALT_LEN = 16
IV_LEN = 16

# Combined payload size
NEW_TOTAL_LEN = TOKEN_LEN + BIN_LEN  # 43 bytes

# Binary data offsets within the 32-byte binary section
SALT_OFFSET = 0
IV_OFFSET = SALT_LEN

# Checksum parameters
CHECKSUM_MODULO = 10

# Field value ranges
FW_MIN = 0
FW_MAX = 9
HW_MIN = 1
HW_MAX = 9
MULTISIGN_MIN = 1
MULTISIGN_MAX = 6
FLAG_MIN = 0
FLAG_MAX = 1

# Field indices in token digits
TOKEN_DIGIT_COUNT = 10
IDX_FW_MAJOR = 0
IDX_FW_MINOR = 1
IDX_FW_PATCH = 2
IDX_HW_VERSION = 3
IDX_MULTISIGN_X = 4
IDX_MULTISIGN_Y = 5
IDX_P_VALUE = 6
IDX_C_VALUE = 7
IDX_BIT_VALUE = 8
IDX_CHECKSUM = 9

# ASCII conversion
ASCII_DIGIT_OFFSET = 48  # ord('0')
ASCII_DIGIT_MIN = 48     # ord('0')
ASCII_DIGIT_MAX = 57     # ord('9')

# Format identifiers
FORMAT_NEW = "new"
FORMAT_LEGACY = "legacy"

# BIT values
BIT_NO_BIOMETRY = 0
BIT_WITH_BIOMETRY = 1

# Legacy format regex patterns
# Pattern WITHOUT BIT: ENC,v1.2.0(2),M-6:3,P-0,C-1 or ENC,v1.1.0_dev2(1),M-6:3,P-0,C-0 or ENC,v1.1.0dev(1),M-6:3,P-0,C-0
LEGACY_NO_BIT_PATTERN = re.compile(
    r"^ENC,v([0-9])\.([0-9])\.([0-9])(?:[_]?[a-zA-Z0-9]+)?\(([1-9])\),"
    r"M-([1-6]):([1-6]),"
    r"P-([01]),"
    r"C-([01])$"
)

# Pattern WITH BIT: ENC,v1.2.0(2),M-6:3,P-0,C-1,BIT1 or ENC,v1.1.0_dev2(1),M-6:3,P-0,C-0,BIT1 or ENC,v1.1.0dev(1),M-6:3,P-0,C-0,BIT1
LEGACY_WITH_BIT_PATTERN = re.compile(
    r"^ENC,v([0-9])\.([0-9])\.([0-9])(?:[_]?[a-zA-Z0-9]+)?\(([1-9])\),"
    r"M-([1-6]):([1-6]),"
    r"P-([01]),"
    r"C-([01]),"
    r"BIT([01])$"
)

# Header template for reconstruction
HEADER_TEMPLATE = "ENC,v{fw_major}.{fw_minor}.{fw_patch}({hw_version}),M-{mx}:{my},P-{p},C-{c},BIT{bit}"


class CodecError(Exception):
    """Exception raised for codec-related errors during encoding/decoding."""
    pass


class DecodeResult:
    """Result of decoding a Record 3 payload.

    Attributes:
        kind: Format type - "new" for compressed format, "legacy" for ASCII format
        header_text: Reconstructed or original header string
        binary32: 32-byte binary data (salt + IV) for new format, None for legacy
    """
    def __init__(self, kind, header_text, binary32=None):
        self.kind = kind
        self.header_text = header_text
        self.binary32 = binary32


def _calculate_checksum(fw_major, fw_minor, fw_patch, hw_version, mx, my, p, c, bit):
    """Calculates checksum for compressed token.

    The checksum is the sum of all field values modulo 10.

    Args:
        fw_major: Firmware major version (0-9)
        fw_minor: Firmware minor version (0-9)
        fw_patch: Firmware patch version (0-9)
        hw_version: Hardware version (1-9)
        mx: Multisign total signers (1-6)
        my: Multisign required signers (1-6)
        p: P-value flag (0-1)
        c: C-value flag (0-1)
        bit: BIT flag (0-1)

    Returns:
        Checksum value (0-9)
    """
    return (fw_major + fw_minor + fw_patch + hw_version + mx + my + p + c + bit) % CHECKSUM_MODULO


def _validate_field_ranges(fw_major, fw_minor, fw_patch, hw_version, mx, my, p, c, bit):
    """Validates that all fields are within their allowed ranges.

    Args:
        fw_major, fw_minor, fw_patch: Firmware version components
        hw_version: Hardware version
        mx, my: Multisign parameters
        p, c, bit: Flag values

    Raises:
        CodecError: If any field is out of range
    """
    if not (FW_MIN <= fw_major <= FW_MAX and
            FW_MIN <= fw_minor <= FW_MAX and
            FW_MIN <= fw_patch <= FW_MAX):
        raise CodecError("Firmware version out of range (0-9)")

    if not (HW_MIN <= hw_version <= HW_MAX):
        raise CodecError("Hardware version out of range (1-9)")

    if not (MULTISIGN_MIN <= mx <= MULTISIGN_MAX and
            MULTISIGN_MIN <= my <= MULTISIGN_MAX):
        raise CodecError("Multisign values out of range (1-6)")

    if p not in (FLAG_MIN, FLAG_MAX) or c not in (FLAG_MIN, FLAG_MAX) or bit not in (FLAG_MIN, FLAG_MAX):
        raise CodecError("Flag values out of range (0-1)")


def _extract_token_digits(token):
    """Extracts and validates digit values from token bytes.

    Args:
        token: 11-byte token starting with 'E'

    Returns:
        List of 10 integer digit values

    Raises:
        CodecError: If token format is invalid
    """
    if token[0:1] != TOKEN_PREFIX_BYTE:
        raise CodecError(f"Token must start with '{TOKEN_PREFIX}'")

    digits_bytes = token[1:]

    if any(d < ASCII_DIGIT_MIN or d > ASCII_DIGIT_MAX for d in digits_bytes):
        raise CodecError("Token contains non-digit characters")

    return [d - ASCII_DIGIT_OFFSET for d in digits_bytes]


def _reconstruct_header(fw_major, fw_minor, fw_patch, hw_version, mx, my, p, c, bit):
    """Reconstructs the full header string from field values.

    Args:
        Field values for firmware version, hardware version, multisign, flags

    Returns:
        Reconstructed header string in format: ENC,v1.2.0(2),M-6:3,P-0,C-1,BIT1
    """
    return HEADER_TEMPLATE.format(
        fw_major=fw_major,
        fw_minor=fw_minor,
        fw_patch=fw_patch,
        hw_version=hw_version,
        mx=mx,
        my=my,
        p=p,
        c=c,
        bit=bit
    )


def decode_new_payload(payload):
    """Decodes a new compressed format payload (43 bytes).

    New format structure:
    - Bytes 0-10: Compressed token (E + 10 digits)
    - Bytes 11-42: Binary data (16 bytes salt + 16 bytes IV)

    Args:
        payload: 43-byte payload in new format

    Returns:
        DecodeResult with kind="new", reconstructed header, and binary data

    Raises:
        CodecError: If payload format is invalid or checksum fails
    """
    if len(payload) != NEW_TOTAL_LEN:
        raise CodecError(f"New payload must be exactly {NEW_TOTAL_LEN} bytes")

    token = payload[:TOKEN_LEN]
    binary_data = payload[TOKEN_LEN:]

    # Extract and validate digits
    digits = _extract_token_digits(token)

    if len(digits) != TOKEN_DIGIT_COUNT:
        raise CodecError(f"Token must contain exactly {TOKEN_DIGIT_COUNT} digits")

    # Parse field values
    fw_major = digits[IDX_FW_MAJOR]
    fw_minor = digits[IDX_FW_MINOR]
    fw_patch = digits[IDX_FW_PATCH]
    hw_version = digits[IDX_HW_VERSION]
    mx = digits[IDX_MULTISIGN_X]
    my = digits[IDX_MULTISIGN_Y]
    p = digits[IDX_P_VALUE]
    c = digits[IDX_C_VALUE]
    bit = digits[IDX_BIT_VALUE]
    checksum = digits[IDX_CHECKSUM]

    # Validate field ranges
    _validate_field_ranges(fw_major, fw_minor, fw_patch, hw_version, mx, my, p, c, bit)

    # Verify checksum
    expected_checksum = _calculate_checksum(fw_major, fw_minor, fw_patch, hw_version, mx, my, p, c, bit)
    if checksum != expected_checksum:
        raise CodecError(f"Checksum mismatch: expected {expected_checksum}, got {checksum}")

    # Reconstruct header
    header = _reconstruct_header(fw_major, fw_minor, fw_patch, hw_version, mx, my, p, c, bit)

    return DecodeResult(
        kind=FORMAT_NEW,
        header_text=header,
        binary32=binary_data
    )


def decode_legacy_header(payload):
    """Decodes a legacy ASCII format header.

    Legacy format can be:
    - Without BIT: ENC,v1.1.0(1),M-3:3,P-0,C-0
    - With BIT: ENC,v1.2.0(2),M-6:3,P-0,C-1,BIT1

    Args:
        payload: ASCII-encoded header bytes

    Returns:
        DecodeResult with kind="legacy", original header text, and no binary data

    Raises:
        CodecError: If payload is not valid ASCII or doesn't match expected patterns
    """
    try:
        header_str = payload.decode('ascii')
    except UnicodeDecodeError as e:
        raise CodecError("Legacy payload must be valid ASCII") from e

    # Try matching with BIT field first
    match_with_bit = LEGACY_WITH_BIT_PATTERN.match(header_str)
    if match_with_bit:
        return DecodeResult(
            kind=FORMAT_LEGACY,
            header_text=header_str,
            binary32=None
        )

    # Try matching without BIT field
    match_without_bit = LEGACY_NO_BIT_PATTERN.match(header_str)
    if match_without_bit:
        return DecodeResult(
            kind=FORMAT_LEGACY,
            header_text=header_str,
            binary32=None
        )

    raise CodecError("Legacy header format not recognized")


def decode_record3_payload(payload):
    """Auto-detects and decodes Record 3 payload format.

    Detection logic:
    - If length is 43 bytes and starts with 'E': new compressed format
    - Otherwise: legacy ASCII format

    Args:
        payload: Record 3 payload bytes

    Returns:
        DecodeResult with decoded information

    Raises:
        CodecError: If payload cannot be decoded
    """
    if len(payload) == NEW_TOTAL_LEN and payload[:1] == TOKEN_PREFIX_BYTE:
        return decode_new_payload(payload)

    return decode_legacy_header(payload)


def extract_salt_from_binary(binary32):
    """Extracts the salt component from the 32-byte binary data.

    Args:
        binary32: 32-byte binary data (salt + IV)

    Returns:
        16-byte salt as bytes
    """
    return binary32[SALT_OFFSET:SALT_OFFSET + SALT_LEN]


def extract_iv_from_binary(binary32):
    """Extracts the IV component from the 32-byte binary data.

    Args:
        binary32: 32-byte binary data (salt + IV)

    Returns:
        16-byte IV as bytes
    """
    return binary32[IV_OFFSET:IV_OFFSET + IV_LEN]
