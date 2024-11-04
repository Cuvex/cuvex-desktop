"""
Author: Ludwing Perez: lp@t2mc.net
SEMILLA3 LLC
https://cuvex.io/
"""
import re
import hashlib
from cuvex.classes import RawCard, KeysDescriptor, Version
from cuvex.exceptions import *
from cuvex.utils import copy_and_clean

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
    return Version(version_info, int(version_parts[0]), int(version_parts[1]),
                   int(patch_parts[0]), final_part)

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
    if len(binary_content) < SIZE_8K_CARD:
        return None
    return bytearray(binary_content[index_begin + prefix_size:])

def process_card(binary_content: bytearray) -> RawCard:
    """Returns a RawCard objects with the different parts of the content of a 
    card (readed from a binary file exported by the Cuvex app) ready to be
    decrypted. This function does not decrypt the content of the card.
    """
    if not binary_content:
        raise EmptyCardException
    
    if len(binary_content) < MINIMUM_CONTENT_LENGTH:
        raise BadFormatContentException

    prefix_size = get_prefix_size(binary_content)
    payload_begin = prefix_size + ALIAS_SIZE
    info_begin = payload_begin + prefix_size + PAYLOAD_SIZE
    multisign_begin = info_begin + prefix_size + CARD_INFO_SIZE

    _, version, signers, _, _ = process_card_info(
        binary_content[info_begin + prefix_size:multisign_begin].decode('utf-8'))

    return RawCard(hashlib.md5(binary_content).hexdigest(), 
                   copy_and_clean(binary_content[prefix_size:payload_begin]), 
                   bytearray(binary_content[payload_begin + prefix_size:info_begin]), 
                   version, 
                   signers, 
                   get_multisign_payload(binary_content, multisign_begin, prefix_size))
