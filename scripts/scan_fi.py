import os
import socket
import sys

fi_host = os.environ.get("FI_HOST", os.environ.get("FI_STANDBY_IP", "198.51.100.1"))

for p in [22, 80, 443, 4430, 2053, 2096, 8443, 23385, 28080, 49752]:
    s = socket.socket()
    s.settimeout(2.0)
    try:
        s.connect((fi_host, p))
        print(f'FI Port {p}: OPEN')
        s.close()
    except Exception as e:
        print(f'FI Port {p}: CLOSED ({e})')
