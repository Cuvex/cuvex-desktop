"""
Author: Ludwing Perez: lp@t2mc.net
SEMILLA3 LLC
https://cuvex.io/
"""
import sys
from cuvex.card_helper import process_card
from cuvex.crypto_helper import decrypt_card
from cuvex.exceptions import *
from cuvex.utils import clean_bytearray, convert_str_to_code_points
from getpass import getpass

def main():
    """Example of use decryption cuvex cards.
    """

    # The file that contains your card's content should be a binary file
    # exported by your cuvex app.
    print('================================================================')
    print("TYPE YOUR CARD's FULL PATH:")
    your_card_content_file_path = input()
    your_passwords = []

    with open(your_card_content_file_path, 'rb') as file:
        card_content = bytearray(file.read())

    ## STEP 1: READ CARD CONTENTS WITHOUT DECRYPTION
    card = process_card(card_content)

    ## For security reasons, it is recomended to zerorized the bytearray 
    ## of the card's content.

    print('================================================================')
    print('CARD INFO:')
    print('ALIAS: ' + card.alias_str)
    print('VERSION: ' + card.version.full_version)
    print('SIGNED BY {} PERSONS. {} SIGNS REQUIRED'.format(card.signs.total, card.signs.required))

    print('================================================================')
    print('TYPE YOUR PASSWORDS')
    counter = 0
    while counter < card.signs.required:
        your_passwords.append(convert_str_to_code_points(getpass(
            "Type password {} of {}: ".format(counter +1, card.signs.required)))
            )
        counter += 1

    ## STEP 2: DECRYPT CONTENT
    card_plain_content = decrypt_card(your_passwords, card)

    ## For security reasons, it is recomended to zerorized the bytearray 
    ## that contains your passwords.

    print('================================================================')
    print('CARD PLAIN CONTENT:')
    print(card_plain_content.content)

    ## For security reasons, it is recomended to zerorized all data.
    card.reset_content()
    card_plain_content.reset_content()
    clean_bytearray(card_content)
    for password in your_passwords:
        clean_bytearray(password)

    sys.exit(0)

if __name__ == '__main__':
    main()
