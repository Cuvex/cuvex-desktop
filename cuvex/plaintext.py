"""
Author: Ludwing Perez: lp@t2mc.net
SEMILLA3 LLC
https://cuvex.io/
"""

def process_plain_text(plain_content: bytearray, prefix_length: int) -> str:
    """Copy the content of the input plain content to a string without
    the prefix ("[bip39]" or "[plain-text]") and any byte at zero, and changes
    the char '¶' (194) with '€' (226).
    """
    if not plain_content:
        return ''
    
    result = ''

    for index in range(len(plain_content)):
        if index < prefix_length:
            continue
        elif plain_content[index] == 0:
            continue
        elif plain_content[index] == 182:
            result += '€'
        else:
            result += chr(plain_content[index])
    return result

def process_seed_phrase(plain_content: bytearray, prefix_length: int) -> str:
    """Process decrypted data bytearray and converts it to a String of a list
    of words as a BIP39/Slip39/Monero seed phrase and a passphrase if it exists.
    """
    if not plain_content:
        return ''

    word_counter = 0
    index_passphrase = plain_content.rfind(b'[passphrase]')
    result = ''

    for index in range(len(plain_content)):
        # replace '¶' (182) with '€' (8364).
        element = 8364 if plain_content[index] == 182 else plain_content[index]

        if element == 0:
            continue

        if index < prefix_length:
            continue

        if index_passphrase == -1 or index < index_passphrase:
            if element == 44: # comma 
                result += '\n{}. '.format(word_counter + 1)
                word_counter += 1
            else:
                result += chr(element)

        if index_passphrase > 0 and index == index_passphrase:
            result += '\n--------------------------------------------------\nPassphrase:\n'

        if index_passphrase > 0 and (index > index_passphrase and index < (index_passphrase + 12)):
            continue

        if index_passphrase > 0 and index >= (index_passphrase + 12):
            result += chr(element)

    return result

def process_full_bip_39(plain_content: bytearray, prefix_length: int) -> str:
    """Process decrypted data as a BIP39 seed phrase with a Derivation path,
    and master and public keys.
    """
    if not plain_content:
        return ''

    word_counter = 0
    index_passphrase = plain_content.rfind(b'{passder}')
    priv_key_index = plain_content.rfind(b'{prikey}')
    pub_key_index = plain_content.rfind(b'{pubkey}')
    comma_count = 0
    result = ''

    for index in range(len(plain_content)):
        # replace '¶' (182) with '€' (8364).
        element = 8364 if plain_content[index] == 182 else plain_content[index]

        if element == 0:
            continue

        if index < prefix_length:
            continue

        if index < index_passphrase:
            if element == 44: # comma 
                result += '\n{}. '.format(word_counter + 1)
                word_counter += 1
            else:
                result += chr(element)

        if index == index_passphrase:
            result += '\n--------------------------------------------------\nPassphrase:\n'

        if (index > index_passphrase and index < (index_passphrase + len('{passder}"'))):
            continue

        if index >= (index_passphrase + len('{passder}"')) and index < priv_key_index:
            # Every comma (ascii=44) followed by a blank space (ascii=32) is 
            # treated like a section separator between sub-sections of the 
            # {passder} data block
            separator_found = element == 44 and plain_content[index + 1] == 32

            # Ignore every quote char (")
            if element == 34:
                continue

            if separator_found and comma_count == 0:
                result += '\n--------------------------------------------------\n'
                comma_count += 1
                continue

            if separator_found and comma_count == 1:
                comma_count += 1
                continue

            if separator_found and comma_count == 2:
                result += '\nDerivation path:\n'
                comma_count += 1
                continue

            if comma_count != 1:
                result += chr(element)

        if index == priv_key_index:
            result += '\n--------------------------------------------------\nMaster private key:\n'

        if index >= (priv_key_index + len('{prikey}')) and index < pub_key_index:
            result += chr(element)

        if index == pub_key_index:
            result += '\n--------------------------------------------------\nMaster public key:\n'

        if index >= (pub_key_index + len('{pubkey}')):
            result += chr(element)

    return result

