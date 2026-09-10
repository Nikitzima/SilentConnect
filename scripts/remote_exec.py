import sys
import os
import time
import socket
import pathlib
import base64
import paramiko

PROXY_HOST = '127.0.0.1'
PROXY_PORT = 10890
NL_HOST = os.environ.get("NL_HOST", os.environ.get("NL_MASTER_IP", "192.0.2.1"))
FI_HOST = os.environ.get("FI_HOST", os.environ.get("FI_STANDBY_IP", "198.51.100.1"))

def socks5_connect(dest_host: str, dest_port: int, proxy_host: str = PROXY_HOST, proxy_port: int = PROXY_PORT):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    s.connect((proxy_host, proxy_port))
    s.sendall(b'\x05\x01\x00')
    resp = s.recv(2)
    if resp != b'\x05\x00':
        raise RuntimeError('SOCKS5 auth failed')
    dest_ip = socket.inet_aton(dest_host)
    s.sendall(b'\x05\x01\x00\x01' + dest_ip + dest_port.to_bytes(2, 'big'))
    resp2 = s.recv(10)
    if len(resp2) < 2 or resp2[1] != 0:
        raise RuntimeError('SOCKS5 connect failed')
    return s

def is_proxy_available(proxy_host: str = PROXY_HOST, proxy_port: int = PROXY_PORT) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        s.connect((proxy_host, proxy_port))
        s.close()
        return True
    except Exception:
        return False

def get_client(target: str, max_retries: int = 5):
    key_path = str(pathlib.Path.home() / '.ssh' / 'id_ed25519')
    key = paramiko.Ed25519Key.from_private_key_file(key_path)

    last_err = None
    for attempt in range(max_retries):
        dest_host = NL_HOST if target == 'nl' else FI_HOST
        
        # 1. Try direct connect first
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(dest_host, username='root', pkey=key, timeout=5, banner_timeout=10, auth_timeout=10)
            return client
        except Exception as direct_err:
            last_err = direct_err

        # 2. For NL, try jumping via FI (rock-solid datacenter link)
        if target == 'nl':
            try:
                jump = paramiko.SSHClient()
                jump.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                jump.connect(FI_HOST, username='root', pkey=key, timeout=5, banner_timeout=10, auth_timeout=10)
                chan = jump.get_transport().open_channel('direct-tcpip', (NL_HOST, 22), ('127.0.0.1', 0))
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(NL_HOST, username='root', pkey=key, sock=chan, timeout=5, banner_timeout=10, auth_timeout=10)
                client._jump_client = jump
                return client
            except Exception as jump_err:
                last_err = jump_err

        # 3. Try local SOCKS5 proxy fallback only if proxy is listening
        if is_proxy_available():
            try:
                sock = socks5_connect(dest_host, 22)
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(dest_host, username='root', pkey=key, sock=sock, banner_timeout=10, auth_timeout=10)
                return client
            except Exception as proxy_err:
                last_err = proxy_err

        time.sleep(2)

    raise last_err

def get_nl_client():
    return get_client('nl')


def run_cmd(target: str, cmd_str: str, timeout: int = 60):
    client = get_client(target)
    try:
        stdin, stdout, stderr = client.exec_command(cmd_str, timeout=timeout)
        stdin.close()
        out = stdout.read().decode('utf-8', errors='replace')
        err = stderr.read().decode('utf-8', errors='replace')
        code = stdout.channel.recv_exit_status()
        return code, out, err
    finally:
        client.close()
        if hasattr(client, '_jump_client'):
            try:
                client._jump_client.close()
            except Exception:
                pass

def upload_file(target: str, local_path: str, remote_path: str, mode: int = 0o644):
    upload_files_batch(target, [(local_path, remote_path, mode)])

def upload_files_batch(target: str, file_tuples: list[tuple[str, str, int]]):
    client = get_client(target)
    try:
        sftp = client.open_sftp()
        for local_path, remote_path, mode in file_tuples:
            remote_dir = os.path.dirname(remote_path)
            if remote_dir and remote_dir != '/':
                try:
                    sftp.stat(remote_dir)
                except IOError:
                    client.exec_command(f"mkdir -p '{remote_dir}'")
            sftp.put(local_path, remote_path)
            sftp.chmod(remote_path, mode)
        sftp.close()
    finally:
        client.close()
        if hasattr(client, '_jump_client'):
            try:
                client._jump_client.close()
            except Exception:
                pass

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print('Usage:')
        print('  python remote_exec.py <nl|fi|both> <command>')
        print('  python remote_exec.py put <nl|fi> <local_path> <remote_path> [mode_octal]')
        sys.exit(1)

    if sys.argv[1] == 'put':
        target = sys.argv[2]
        local_path = sys.argv[3]
        remote_path = sys.argv[4]
        mode = int(sys.argv[5], 8) if len(sys.argv) > 5 else 0o644
        upload_file(target, local_path, remote_path, mode)
        print(f"Uploaded {local_path} -> {target}:{remote_path}")
        sys.exit(0)

    target = sys.argv[1]
    command = ' '.join(sys.argv[2:])
    if target in ('nl', 'fi'):
        code, out, err = run_cmd(target, command)
        try:
            print(out, end='')
        except UnicodeEncodeError:
            print(out.encode('ascii', errors='replace').decode('ascii'), end='')
        if err:
            try:
                print(err, file=sys.stderr, end='')
            except UnicodeEncodeError:
                print(err.encode('ascii', errors='replace').decode('ascii'), file=sys.stderr, end='')
        sys.exit(code)
    elif target == 'both':
        print('=== NL ===')
        code1, out1, err1 = run_cmd('nl', command)
        try:
            print(out1, end='')
        except UnicodeEncodeError:
            print(out1.encode('ascii', errors='replace').decode('ascii'), end='')
        if err1:
            try:
                print(err1, file=sys.stderr, end='')
            except UnicodeEncodeError:
                print(err1.encode('ascii', errors='replace').decode('ascii'), file=sys.stderr, end='')
        print('=== FI ===')
        code2, out2, err2 = run_cmd('fi', command)
        try:
            print(out2, end='')
        except UnicodeEncodeError:
            print(out2.encode('ascii', errors='replace').decode('ascii'), end='')
        if err2:
            try:
                print(err2, file=sys.stderr, end='')
            except UnicodeEncodeError:
                print(err2.encode('ascii', errors='replace').decode('ascii'), file=sys.stderr, end='')
        sys.exit(code1 or code2)
