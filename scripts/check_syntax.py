#!/usr/bin/env python3
import subprocess
import os

scripts_to_test = ['scripts/promote_fi.sh', 'scripts/demote_fi.sh', 'scripts/cf-failover-dns.sh']

for f in scripts_to_test:
    with open(f, 'r', encoding='utf-8') as fh:
        code = fh.read()
    p = subprocess.Popen(
        ['python', 'scripts/remote_exec.py', 'nl', 'bash -n'],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        encoding='utf-8'
    )
    out, err = p.communicate(input=code)
    print(f"[{f}] exit: {p.returncode}, err: {err.strip()}, out: {out.strip()}")
