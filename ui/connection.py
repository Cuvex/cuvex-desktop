"""
Author: Ludwing Perez: lp@t2mc.net
SEMILLA3 LLC
https://cuvex.io/
"""

import socket

SERVER = '8.8.8.8'
PORT = 53 # 80
TIMEOUT = 3

def check_connection():
    """Verify if there is internet connection by sending a ping to Google DNS
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT)
    try:
        sock.connect((SERVER, PORT))
        return True
    except socket.error as ex:
        return False
    finally:
        pass