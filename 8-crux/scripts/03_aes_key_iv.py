#!/usr/bin/env python3
"""Stage 3: recover the AES key and IV from a memory snapshot.

Key: Go's crypto/aes keeps the *expanded* key schedule. Its first Nk words are the raw
key, and word Nk must equal  w[0] ^ SubWord(RotWord(w[Nk-1])) ^ Rcon[1].
Scanning memory for that relation finds the schedule without any symbols.

IV: we know our ciphertext C. D = AES_ECB_decrypt(key, C[0:16]).
CBC says P0 = D ^ IV, and both P0 and IV live somewhere in memory after the call,
so look for a 16-byte value X in memory such that D ^ X is also in memory.

usage: node harness.js <chal> "$(python3 -c 'import base64;print(base64.b64encode(bytes(range(100,132))).decode())')" --dump run
       python3 03_aes_key_iv.py run
"""
import struct, sys
from Crypto.Cipher import AES

a = open(sys.argv[1] + '.before.bin', 'rb').read()
m = open(sys.argv[1] + '.after.bin', 'rb').read()

def sbox():
    p = q = 1; s = [0] * 256
    while True:
        p = p ^ ((p << 1) & 0xff) ^ (0x1b if p & 0x80 else 0)
        q ^= q << 1; q ^= q << 2; q ^= q << 4; q &= 0xff
        if q & 0x80: q ^= 0x09
        r = lambda x, k: ((x << k) | (x >> (8 - k))) & 0xff
        s[p] = q ^ r(q, 1) ^ r(q, 2) ^ r(q, 3) ^ r(q, 4) ^ 0x63
        if p == 1: break
    s[0] = 0x63
    return s
S = sbox()
sub = lambda w: (S[w >> 24] << 24) | (S[(w >> 16) & 255] << 16) | (S[(w >> 8) & 255] << 8) | S[w & 255]
rot = lambda w: ((w << 8) | (w >> 24)) & 0xffffffff

key = None
for off in range(0, len(m) - 64, 4):
    w = struct.unpack_from('<9I', m, off)
    if w[0] == 0 and w[1] == 0:
        continue
    for nk in (4, 6, 8):
        if w[nk] == w[0] ^ sub(rot(w[nk - 1])) ^ 0x01000000:
            key = b''.join(struct.pack('>I', x) for x in w[:nk])
            print(f'[+] AES-{nk*32} key schedule at mem 0x{off:x}')
            print(f'    key = {key.hex()}')
    if key:
        break

C = bytes(range(100, 132))                      # the ciphertext we submitted
D = AES.new(key, AES.MODE_ECB).decrypt(C[:16])
changed = {}
for i in range(len(m)):
    if a[i] != m[i]:
        for s in range(max(0, i - 15), i + 1):
            changed.setdefault(m[s:s + 16], s)
x = lambda p, q: bytes(u ^ v for u, v in zip(p, q))
for blk, at in changed.items():
    if blk.count(0) < 8 and x(D, blk) in changed:
        print(f'[+] candidate IV {blk.hex()} at 0x{at:x}  (pairs with block at 0x{changed[x(D, blk)]:x})')
