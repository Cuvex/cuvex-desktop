"""
Author: Ludwing Perez: lp@t2mc.net
SEMILLA3 LLC
https://cuvex.io/
"""
import re
import hashlib
from cuvex.classes import RawCard, KeysDescriptor, Version, CryptoParams
from cuvex.exceptions import *
from cuvex.utils import copy_and_clean
from cuvex.codec import (
    decode_record3_payload,
    CodecError,
    extract_salt_from_binary,
    extract_iv_from_binary,
    FORMAT_NEW,
    FORMAT_LEGACY
)

NDEF_PREFIX_SIZE = 3 # Default prefix for NDEF protocol records
CUVEX_PREFIX_SIZE = 9 # Old prefix used by Cuvex App 'record_x:'
NO_PREFIX = 0
BEGIN_ALIAS_UID = 0
BEGIN_PAYLOAD = 28
BEGIN_CARD_INFO = 799
BEGIN_MULTISIGN = 852

ALIAS_SIZE = 25
PAYLOAD_SIZE = 768
CARD_INFO_SIZE = 50
MULTISIGN_SIZE = 700

# To calculate the minimum length of the card's content, the multisign block
# is not taken in count because that block is optional.
MINIMUM_CONTENT_LENGTH = ALIAS_SIZE + PAYLOAD_SIZE + CARD_INFO_SIZE
SIZE_8K_CARD = MINIMUM_CONTENT_LENGTH + MULTISIGN_SIZE

# BIT field markers in header
BIT_MARKER_PREFIX = ",BIT"
BIT_NO_BIOMETRY = "BIT0"
BIT_WITH_BIOMETRY = "BIT1"

# New format delimiters (NDEF)
DELIMITER_ALIAS = bytes.fromhex('02413A')      # Record 1 (ALIAS) start
DELIMITER_PAYLOAD = bytes.fromhex('02433A')    # Record 2 (PAYLOAD) start
DELIMITER_INFO = bytes.fromhex('02493A')       # Record 3 (INFO) start
DELIMITER_MULTISIGN = bytes.fromhex('024D3A')  # Record 4 (MULTISIGN) start (optional)

# Format detection patterns (both preceded by "I:")
# New format: I: + compressed token (E + 10 digits)
NEW_FORMAT_PATTERN = re.compile(r'I:E[0-9]{10}')

# Legacy format: I: + full ASCII header (based on LEGACY_WITH_BIT_PATTERN from codec.py)
LEGACY_FORMAT_PATTERN = re.compile(
    r'I:ENC,v[0-9]\.[0-9]\.[0-9](?:[_]?[a-zA-Z0-9]+)?\([1-9]\),'
    r'M-[1-6]:[1-6],'
    r'P-[01],'
    r'C-[01]'
    r'(?:,BIT[01])?'  # BIT field is optional
)

def get_prefix_size(binary_data: bytearray) -> int:
    """Calculates the length of the prefix of each card registry.
    For a raw NDEF card, the protocol specify a delimiter of 3 bytes between every
    register.  For older versions of the card's file, the prefix was in the form
    of 'record_N' where N was a digit.  This format is mantained only for 
    retrocompatibility.
    """
    if binary_data.startswith(bytes.fromhex('02413A')):
        return NDEF_PREFIX_SIZE
    if binary_data.startswith(b'record_0'):
        return CUVEX_PREFIX_SIZE
    return NO_PREFIX

def process_card_version(version_info: str) -> Version:
    """Extracts the version data from the version string. This string is in the
    format "v1.1.0(1)".  A Version object is returned with the whole data and
    in its parts as integers.
    """
    version_parts = re.sub(r'[vV]', '', version_info).split('.')
    patch_parts = version_parts[2].partition('(')
    final_part = patch_parts[2].replace(')', '') if patch_parts[2] else None

    version_part_major = re.sub(r'\D', '', '0' if not version_parts[0] else version_parts[0])
    version_part_major = '0' if not version_part_major else version_part_major

    version_part_minor = re.sub(r'\D', '', '0' if not version_parts[1] else version_parts[1])
    version_part_minor = '0' if not version_part_minor else version_part_minor

    last_part = re.sub(r'\D', '', '0' if not patch_parts[0] else patch_parts[0])
    last_part = '0' if not last_part else last_part

    return Version(version_info, 
                   int(version_part_major), 
                   int(version_part_minor),
                   int(last_part), 
                   final_part)

def process_card_signers(signers: str) -> KeysDescriptor:
    """Returns a KeysDescriptor that describes how the card was cyphered.
    The original descriptor is in the format "M-X:Y" where X is the total of 
    passwords used to generate the cyphered block. Y is the minimum number of
    passwords required to decrypt the secret block.
    """
    sign_data = signers.replace('M-', '')

    sign_parts = sign_data.split(':')

    if len(sign_parts) < 2:
        return KeysDescriptor(int(sign_parts[0]), int(sign_parts[0]))
    
    return KeysDescriptor(int(sign_parts[0]), int(sign_parts[1]))

def process_card_info(info: str) -> tuple:
    """Process the card's description block. The block is in the format
    "ENC,v1.1.0(1),M-3:1,P-0,C-0" where each part is separated by a coma (,).
    The first part indicates that the card is encrypted, the second indicates
    the version of the card, the third indicates how the card was encrypted,
    the fourth indicates if the card is compressed, and the fifth part indicates
    if the card is a clone.  The splited and processed parts are returned as a
    tuple.
    """
    parts = info.split(',')
    return (
        parts[0],
        process_card_version(parts[1]),
        process_card_signers(parts[2]),
        parts[3],
        parts[4],
    )

def get_multisign_payload(binary_content: bytearray, index_begin: int,
                          prefix_size: int) -> bytearray:
    """Returns the part of the card's content related with multisign. This part
    is only presents in 8K cards and only if the card was cyphered with the
    multisign activated.
    """
    return bytearray(binary_content[index_begin + prefix_size:])

def detect_format(binary_content: bytearray) -> str:
    """Detects card format by searching for patterns in ASCII representation."""
    ascii_content = binary_content.decode('ascii', errors='replace')

    if NEW_FORMAT_PATTERN.search(ascii_content):
        return FORMAT_NEW
    if LEGACY_FORMAT_PATTERN.search(ascii_content):
        return FORMAT_LEGACY

    raise BadFormatContentException("Cannot detect card format")

def extract_with_delimiters(binary_content: bytearray) -> tuple:
    """Extracts records using NDEF delimiters (new format).

    Returns:
        (alias_data, payload_data, record3_data, multisign_data)
    """
    alias_start = binary_content.find(DELIMITER_ALIAS)
    payload_start = binary_content.find(DELIMITER_PAYLOAD)
    info_start = binary_content.find(DELIMITER_INFO)

    if alias_start == -1 or payload_start == -1 or info_start == -1:
        raise BadFormatContentException("Missing required delimiters")

    multisign_start = binary_content.find(DELIMITER_MULTISIGN)

    alias_data = binary_content[alias_start + len(DELIMITER_ALIAS):payload_start]
    payload_data = binary_content[payload_start + len(DELIMITER_PAYLOAD):info_start]

    if multisign_start != -1:
        record3_data = binary_content[info_start + len(DELIMITER_INFO):multisign_start]
        multisign_data = binary_content[multisign_start + len(DELIMITER_MULTISIGN):]
    else:
        record3_data = binary_content[info_start + len(DELIMITER_INFO):]
        multisign_data = bytearray()

    return alias_data, payload_data, record3_data, multisign_data

def extract_with_fixed_length(binary_content: bytearray) -> tuple:
    """Extracts records using fixed lengths (legacy format).

    Returns:
        (alias_data, payload_data, record3_data, multisign_data)
    """
    if len(binary_content) < MINIMUM_CONTENT_LENGTH:
        raise BadFormatContentException

    prefix_size = get_prefix_size(binary_content)
    payload_begin = prefix_size + ALIAS_SIZE
    info_begin = payload_begin + prefix_size + PAYLOAD_SIZE
    multisign_begin = info_begin + prefix_size + CARD_INFO_SIZE

    alias_data = binary_content[prefix_size:payload_begin]
    payload_data = binary_content[payload_begin + prefix_size:info_begin]
    record3_data = binary_content[info_begin + prefix_size:multisign_begin]
    multisign_data = get_multisign_payload(binary_content, multisign_begin, prefix_size)

    return alias_data, payload_data, record3_data, multisign_data

def create_crypto_params(decode_result) -> CryptoParams:
    """Creates CryptoParams based on decoded format."""
    crypto_params = CryptoParams()

    if decode_result.kind == FORMAT_NEW:
        crypto_params.use_pbkdf2 = True
        crypto_params.use_permutations = False
        crypto_params.has_biometry = False
        crypto_params.salt = bytearray(extract_salt_from_binary(decode_result.binary32))
        crypto_params.iv = bytearray(extract_iv_from_binary(decode_result.binary32))
    else:
        crypto_params.use_pbkdf2 = False
        crypto_params.use_permutations = True
        crypto_params.has_biometry = False
        crypto_params.salt = None
        crypto_params.iv = None

    return crypto_params

def _validate_card_content(binary_content: bytearray) -> None:
    """Validates binary content is not empty.

    Args:
        binary_content: Binary card data

    Raises:
        EmptyCardException: If binary content is empty
    """
    if not binary_content:
        raise EmptyCardException

def _extract_card_records(binary_content: bytearray) -> tuple:
    """Extracts all card records based on detected format.

    Args:
        binary_content: Binary card data

    Returns:
        Tuple of (alias_data, payload_data, record3_data, multisign_data, card_format)

    Raises:
        BadFormatContentException: If format detection or extraction fails
    """
    card_format = detect_format(binary_content)

    if card_format == FORMAT_NEW:
        alias_data, payload_data, record3_data, multisign_data = extract_with_delimiters(binary_content)
    else:
        alias_data, payload_data, record3_data, multisign_data = extract_with_fixed_length(binary_content)
        # Strip padding for legacy format
        record3_data = bytes(record3_data).rstrip(b'\x00')

    return alias_data, payload_data, record3_data, multisign_data, card_format

def _decode_and_validate_header(record3_data: bytes) -> tuple:
    """Decodes Record 3 and validates biometry requirement.

    Args:
        record3_data: Raw Record 3 binary data

    Returns:
        Tuple of (decode_result, header_text)

    Raises:
        BadFormatContentException: If decode fails
        BiometryNotSupportedException: If BIT1 is present (biometry required)
    """
    try:
        decode_result = decode_record3_payload(record3_data)
    except CodecError as e:
        raise BadFormatContentException(f"Invalid Record 3 format: {e}")

    if BIT_WITH_BIOMETRY in decode_result.header_text:
        raise BiometryNotSupportedException(
            "Card requires biometric authentication and cannot be decrypted on desktop"
        )

    return decode_result, decode_result.header_text

def _build_raw_card(binary_content: bytearray, alias_data: bytearray,
                    payload_data: bytearray, multisign_data: bytearray,
                    header_text: str, crypto_params: CryptoParams) -> RawCard:
    """Builds RawCard object from parsed components.

    Args:
        binary_content: Original binary card data (for hash)
        alias_data: Extracted alias bytes
        payload_data: Encrypted payload bytes
        multisign_data: Multisign data (empty if not multisign card)
        header_text: Decoded header string
        crypto_params: Cryptographic parameters

    Returns:
        Fully constructed RawCard object
    """
    _, version, signers, _, _ = process_card_info(header_text)

    return RawCard(
        hashlib.md5(binary_content).hexdigest(),
        copy_and_clean(bytearray(alias_data)),
        bytearray(payload_data),
        version,
        signers,
        bytearray(multisign_data),
        crypto_params
    )

def process_card(binary_content: bytearray) -> RawCard:
    """Returns a RawCard objects with the different parts of the content of a
    card (readed from a binary file exported by the Cuvex app) ready to be
    decrypted. This function does not decrypt the content of the card.

    Supports both legacy and new Cuvex BIT formats:
    - Legacy: Fixed-length records with ASCII header
    - New: Delimiter-based records with compressed header + PBKDF2 params

    This function orchestrates the card processing pipeline by delegating to
    specialized helper functions for validation, extraction, decoding, and
    object construction.

    Raises:
        EmptyCardException: If binary content is empty
        BadFormatContentException: If binary content is invalid
        BiometryNotSupportedException: If card requires biometric authentication (BIT1)
        CodecError: If record 3 decoding fails
    """
    _validate_card_content(binary_content)

    alias_data, payload_data, record3_data, multisign_data, card_format = \
        _extract_card_records(binary_content)

    decode_result, header_text = _decode_and_validate_header(record3_data)

    crypto_params = create_crypto_params(decode_result)

    return _build_raw_card(
        binary_content, alias_data, payload_data, multisign_data,
        header_text, crypto_params
    )
