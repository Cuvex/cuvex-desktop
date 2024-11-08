"""
This is a setup.py script generated by py2applet

Usage:
    python setup.py py2app
"""

from setuptools import setup

APP = ['main.py']
APP_NAME = 'cuvex'
DATA_FILES = [('assets',['version.txt','assets/logotipo_cuvex_claro.png'],),]
OPTIONS = {
    'iconfile': './assets/default-icon.icns',
    'plist': {
        'CFBundleName': APP_NAME,
        'CFBundleDisplayName': APP_NAME,
        'CFBundleGetInfoString': "Cuvex Decryption Tool",
        'CFBundleIdentifier': "io.cuvex.osx.cuvex",
        'CFBundleVersion': "1.1.0",
        'CFBundleShortVersionString': "1.1.0",
        'NSHumanReadableCopyright': u"Copyright © 2024, Semilla3, All Rights Reserved"
    }
}

setup(
    name=APP_NAME,
    app=APP,
    data_files=DATA_FILES,
    options={'py2app': OPTIONS},
    setup_requires=['py2app'],
)
