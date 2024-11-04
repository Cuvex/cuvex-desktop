"""
Author: Ludwing Perez: lp@t2mc.net
SEMILLA3 LLC
https://cuvex.io/
"""
import os
from sys import platform

if platform == "darwin":
    _BASE_DIR = os.path.abspath(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
    ASSETS_DIR = os.path.join(_BASE_DIR, 'assets')

    with open(os.path.join(ASSETS_DIR, 'version.txt'), 'r') as file:
        VERSION = file.read()
else:
    _BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    ASSETS_DIR = os.path.join(_BASE_DIR, 'assets')

    with open(os.path.join(_BASE_DIR, 'version.txt'), 'r') as file:
        VERSION = file.read()