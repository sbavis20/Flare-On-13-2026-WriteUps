#!/usr/bin/env python3
"""Final solver: build the unique Pratt certificate for N and wrap it the way check() expects.

  input = base64( AES-256-CBC(key, iv, PKCS7( serialize(cert(N)) )) )

Node format (all integers little-endian):
  leaf (the prime 2) : 00
  node               : 01 | u32 n | n * (u32 len | child) | u32 lenP | P | u32 lenW | W
  P, W are little-endian magnitudes with no trailing zero byte.

Rules enforced by main.Kd5oA2q (verifyNode):
  * children are the full factorisation of P-1, with multiplicity, sorted ascending
  * W^(P-1) == 1 mod P and W^((P-1)/q) != 1 mod P for every child q
  * W is the SMALLEST such witness (every 2..W-1 is tried and must fail)
"""
import base64, struct, sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from sympy import factorint, isprime

N   = 0xd389dfbb379a02ccda7a4ab0b327e8e3655a3c96447c1b5578bee179c930e261
KEY = bytes.fromhex('cabeba7ad156801d1c82381c7cb8a3c406ae2c3cd168a96cd8373684cdbf8723')
IV  = bytes.fromhex('5ff26040c4c20b9f2ffdefa7ecf65d91')

def le(n):
    return n.to_bytes((n.bit_length() + 7) // 8, 'little')

def serialize(p, w, children):
    out = b'\x01' + struct.pack('<I', len(children))
    for c in children:
        out += struct.pack('<I', len(c)) + c
    return out + struct.pack('<I', len(le(p))) + le(p) + struct.pack('<I', len(le(w))) + le(w)

cache = {}
def cert(p, depth=0):
    if p == 2:
        return b'\x00'
    if p in cache:
        return cache[p]
    assert isprime(p)
    f = factorint(p - 1)
    qs = sorted(f)
    w = 2
    while not all(pow(w, (p - 1) // q, p) != 1 for q in qs):
        w += 1
    print(f"{'  ' * depth}{p}  W={w}  p-1 = " + ' * '.join(f'{q}^{e}' if e > 1 else str(q) for q, e in sorted(f.items())))
    children = [cert(q, depth + 1) for q in qs for _ in range(f[q])]
    cache[p] = serialize(p, w, children)
    return cache[p]

if __name__ == '__main__':
    target = int(sys.argv[1], 0) if len(sys.argv) > 1 else N
    c = cert(target)
    open('cert.bin', 'wb').write(c)
    ct = AES.new(KEY, AES.MODE_CBC, IV).encrypt(pad(c, 16))
    b64 = base64.b64encode(ct).decode()
    open('answer.txt', 'w').write(b64)
    print(f'\n[+] certificate: {len(c)} bytes -> cert.bin')
    print(f'[+] answer: {len(b64)} base64 chars -> answer.txt')
