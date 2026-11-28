#!/usr/bin/env python3
"""Stage 1: triage main.wasm.

- lists wasm sections
- finds the Go version string
- locates Go's pclntab by its *header shape* (garble changed the magic)
- rebuilds the function-name table and maps names to wasm function indices

usage: python3 01_triage.py path/to/main.wasm
"""
import re, struct, sys, json

d = open(sys.argv[1], 'rb').read()

def leb(p):
    r = s = 0
    while True:
        b = d[p]; p += 1
        r |= (b & 0x7f) << s; s += 7
        if b < 0x80:
            return r, p

# ---- 1. sections -----------------------------------------------------------
SEC = {0: 'custom', 1: 'type', 2: 'import', 3: 'function', 4: 'table', 5: 'memory',
       6: 'global', 7: 'export', 9: 'elem', 10: 'code', 11: 'data'}
print('[*] sections')
p, data_off = 8, None
while p < len(d):
    sid = d[p]; size, q = leb(p + 1)
    print(f'    {SEC.get(sid, sid):9} off=0x{q:06x} size={size}')
    if sid == 11:
        data_off = q
    p = q + size

ver = set(re.findall(rb'go1\.\d+(?:\.\d+)?', d))
print('[*] Go version strings:', [v.decode() for v in ver])

# ---- 2. rebuild linear memory from active data segments -------------------
p = data_off
n, p = leb(p)
mem = bytearray(64 << 20)
for _ in range(n):
    _, p = leb(p)                       # flags (0 = active, memory 0)
    assert d[p] == 0x41
    off, p = leb(p + 1)                 # i32.const offset
    assert d[p] == 0x0b; p += 1         # end
    ln, p = leb(p)
    mem[off:off + ln] = d[p:p + ln]; p += ln
print(f'[*] {n} data segments loaded into a memory image')

# ---- 3. find pclntab by structure, not magic -------------------------------
# Go 1.20+ header: magic u32, pad u16=0, minLC u8=1, ptrSize u8=8, then 8 u64:
# nfunc, nfiles, textStart, funcnameOffset, cuOffset, filetabOffset, pctabOffset, pclnOffset
hdr = None
for m in re.finditer(rb'\x00\x00\x01\x08', mem[:8 << 20]):
    h = m.start() - 4
    v = struct.unpack('<8Q', mem[h + 8:h + 72])
    if 1000 < v[0] < 100000 and v[1] < 10000 and all(x < (64 << 20) for x in v[3:]):
        hdr = h
        break
magic = mem[hdr:hdr + 4][::-1].hex()
nfunc, nfiles, text, fno, cuo, fto, pco, plo = struct.unpack('<8Q', mem[hdr + 8:hdr + 72])
print(f'[*] pclntab at mem 0x{hdr:x}  magic=0x{magic} (expected 0xfffffff1)  nfunc={nfunc}')

# ---- 4. function names -----------------------------------------------------
ft = hdr + plo
nimports = 20          # gojs.* imports come first in the wasm function index space
names = {}
for k in range(nfunc):
    entry, fo = struct.unpack('<II', mem[ft + 8 * k:ft + 8 * k + 8])
    nameoff = struct.unpack('<i', mem[ft + fo + 4:ft + fo + 8])[0]
    s = hdr + fno + nameoff
    e = mem.index(0, s)
    names[k + nimports] = mem[s:e].decode(errors='replace')

json.dump(names, open('names.json', 'w'), indent=0)
print('[*] wrote names.json (wasm func index -> Go name)')
print('[*] package main:')
for i, nm in names.items():
    if nm.startswith('main.'):
        print(f'    func[{i}]  {nm}')
