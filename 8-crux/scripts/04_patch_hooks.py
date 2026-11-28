#!/usr/bin/env python3
"""Stage 4 helper: add an entry hook to chosen wasm functions.

Each hooked function gets this prologue (only on fresh entry, i.e. param0 == 0;
Go/wasm re-enters functions with a resume PC in param0 after a goroutine switch):

    local.get 0 ; i32.eqz ; if
        i32.const 0x70000000+funcIndex
        call 5                       ;; import gojs.runtime.nanotime1
    end

nanotime1 normally receives Go's SP. A value >= 0x70000000 can never be a real SP,
so trace.js treats it as "function N was entered" and reads the Go stack arguments.
No new imports, no type changes, the module still validates.

usage: python3 04_patch_hooks.py main.wasm patched.wasm 3251 3274
"""
import sys
src, dst, lo, hi = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
d = open(src, 'rb').read()

def leb(p):
    r = s = 0
    while True:
        b = d[p]; p += 1; r |= (b & 0x7f) << s; s += 7
        if b < 0x80: return r, p
def uleb(v):
    o = b''
    while True:
        b = v & 0x7f; v >>= 7
        if v: o += bytes([b | 0x80])
        else: return o + bytes([b])
def sleb(v):
    o = b''
    while True:
        b = v & 0x7f; v >>= 7
        if v == 0 and not b & 0x40: return o + bytes([b])
        o += bytes([b | 0x80])

p = 8
while True:
    sid = d[p]; size, body = leb(p + 1)
    if sid == 10: hdr = p; break
    p = body + size
cnt, p = leb(body)
out = [uleb(cnt)]
for k in range(cnt):
    sz, q = leb(p); idx = k + 20; fb = d[q:q + sz]
    if lo <= idx <= hi:
        nl, r = leb(q)
        for _ in range(nl):
            _, r = leb(r); r += 1
        hook = b'\x20\x00\x45\x04\x40' + b'\x41' + sleb(0x70000000 + idx) + b'\x10\x05\x0b'
        fb = d[q:r] + hook + d[r:q + sz]
    out.append(uleb(len(fb)) + fb); p = q + sz
nb = b''.join(out)
open(dst, 'wb').write(d[:hdr] + b'\x0a' + uleb(len(nb)) + nb + d[body + size:])
print(f'[+] hooked funcs {lo}..{hi} -> {dst}')
