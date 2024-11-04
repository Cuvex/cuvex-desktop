"""
Author: Ludwing Perez: lp@t2mc.net
SEMILLA3 LLC
https://cuvex.io/
"""

class FewerPasswordsThanRequiredException(Exception):
    pass

class EmptyCardException(Exception):
    pass

class BadFormatContentException(Exception):
    pass

class CardVersionNotSupportedException(Exception):
    pass