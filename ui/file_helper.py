"""
Author: Ludwing Perez: lp@t2mc.net
SEMILLA3 LLC
https://cuvex.io/
"""

def read_binary_file(file_path: str) -> bytearray:
    """Reads the content of the file pointed by the input path as binary content.
    """
    with open(file_path, 'rb') as file:
        return bytearray(file.read())