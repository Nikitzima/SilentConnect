#!/usr/bin/env python3
import sys, socket, threading

def pipe(src, dst):
    try:
        while True:
            data = src.read(4096) if hasattr(src, 'read') else src.recv(4096)
            if not data: break
            if hasattr(dst, 'write'):
                dst.write(data)
                dst.flush()
            else:
                dst.sendall(data)
    except Exception:
        pass

if __name__ == '__main__':
    proxy_host, proxy_port = sys.argv[1], int(sys.argv[2])
    target_host, target_port = sys.argv[3], int(sys.argv[4])
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((proxy_host, proxy_port))
    s.sendall(b'\x05\x01\x00')
    if s.recv(2) != b'\x05\x00': sys.exit(1)
    host_bytes = target_host.encode('ascii')
    req = b'\x05\x01\x00\x03' + bytes([len(host_bytes)]) + host_bytes + target_port.to_bytes(2, 'big')
    s.sendall(req)
    resp = s.recv(4)
    if len(resp) < 4 or resp[1] != 0: sys.exit(1)
    if resp[3] == 1: s.recv(6)
    elif resp[3] == 3:
        l = s.recv(1)[0]
        s.recv(l + 2)
    elif resp[3] == 4: s.recv(18)
    
    t1 = threading.Thread(target=pipe, args=(sys.stdin.buffer, s), daemon=True)
    t1.start()
    pipe(s, sys.stdout.buffer)
