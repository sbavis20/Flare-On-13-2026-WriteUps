#!/usr/bin/env python3
"""
Flare-On 13 (2026) - Challenge 7: FlareCalc - offline solver.

Reproduces the payload's logic without running FlareCalc.exe:
  1. Carve the payload hidden in the Authenticode certificate table.
  2. Parse the 1035 encrypted "records" stored under OID 1.3.6.1.4.1.1337.1.
  3. Decrypt records with the two-stage scheme keyed by "8675309-88224646-31428571".
  4. Walk the per-character password state machine (each node is a decrypted x64
     snippet, executed with Unicorn) from node 0xCB7A until it reaches 0x1185.
  5. Run record 0x1185 (XTEA) on record 0x2706 with the final 32-byte state as key.

Usage:  python solve.py FlareCalc.exe
Needs:  pip install unicorn
"""
import hashlib, struct, sys, time
from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_64
from unicorn.x86_const import *

KEYSTR = b"8675309-88224646-31428571"   # r1-r2-(1e7*r3) from the calculator gate
START_NODE, ACCEPT_NODE, FLAG_CT = 0xCB7A, 0x1185, 0x2706
OID_1337 = bytes.fromhex("2b060104018a3901")  # 1.3.6.1.4.1.1337.1

# ---------- 1. carve the payload from the certificate table ----------
def carve_payload(exe):
    pe = struct.unpack_from("<I", exe, 0x3C)[0]
    opt = pe + 24
    sec_off, sec_size = struct.unpack_from("<II", exe, opt + 112 + 4 * 8)  # data dir 4
    return exe[sec_off: sec_off + 0x8149D]   # FUN_1400019d0 reads exactly 0x8149D bytes

# ---------- 2. parse records (mirrors payload function 0xFF3A) ----------
def tlv(b, i):
    t, l = b[i], b[i + 1]; i += 2
    if l & 0x80:
        n = l & 0x7F; l = int.from_bytes(b[i:i + n], "big"); i += n
    return t, l, i

def parse_records(blob):
    p = blob.find(OID_1337) + len(OID_1337)
    _, _, p = tlv(blob, p)            # OCTET STRING wrapper
    _, outer_len, p = tlv(blob, p)    # SEQUENCE of records
    end, recs = p + outer_len, {}
    while p < end:
        _, rec_len, q = tlv(blob, p)  # SEQUENCE { INTEGER id, OCTET STRING data }
        _, il, q2 = tlv(blob, q)
        rid = int.from_bytes(blob[q2:q2 + il], "big")
        _, dl, q3 = tlv(blob, q2 + il)
        recs[rid] = blob[q3:q3 + dl]
        p = q + rec_len
    return recs

# ---------- 3. record decryption (payload functions 0x1036A and 0x101E6) ----------
def lcg(x):
    return (x * 1103515245 + 12345) & 0xFFFFFFFF

def seed_hash(s):                      # payload 0xFDAA: h = h*129 + signed byte
    h = 0x2437
    for c in s:
        h = ((h << 7) + h + (c - 256 if c >= 128 else c)) & 0xFFFFFFFF
    return h                           # == 0x429057CE for KEYSTR

SEED = seed_hash(KEYSTR)

def stage1_xor(data, key16):           # 0x1036A: h = h*31 + k, then LCG low byte XOR
    h = 0
    for c in key16:
        h = ((h << 5) - h + c) & 0xFFFFFFFF
    out = bytearray()
    for c in data:
        h = lcg(h); out.append(c ^ (h & 0xFF))
    return bytes(out)

def stage2_skip(data):                 # 0x101E6: keep 1 byte, skip (rand%3)+1
    st, out, i = SEED, bytearray(), 0
    while i < len(data):
        out.append(data[i]); i += 1
        st = lcg(st); r = st % 3 + 1
        for _ in range(r):
            st = lcg(st)
        i += r
    return bytes(out)

def decrypt_record(recs, rid):
    key = hashlib.md5(KEYSTR + struct.pack("<I", rid)).digest()
    return stage2_skip(stage1_xor(recs[rid], key))

# ---------- 4. run decrypted node code with Unicorn ----------
CODE, DATA, STK, RET = 0x100000, 0x200000, 0x300000, 0x400000
mu = Uc(UC_ARCH_X86, UC_MODE_64)
for base in (CODE, DATA, STK, RET):
    mu.mem_map(base, 0x40000)

def skip_padding(code):
    # Every node spins `for i in range(1_000_000): acc += i` and then removes
    # 0x6A4AE6E0 (== sum(range(1_000_000)) mod 2**32) with either `sub 0x6A4AE6E0`
    # or `add 0x95B51920`, so the term is always 0. Shrinking the loop to 1
    # iteration and zeroing that constant gives the same result ~1000x faster.
    c = code.replace(bytes.fromhex("40420f00"), bytes.fromhex("01000000"))
    c = c.replace(bytes.fromhex("e0e64a6a"), bytes(4))
    return c.replace(bytes.fromhex("2019b595"), bytes(4))

def call(code, rcx, rdx, r8=0):
    mu.ctl_remove_cache(CODE, CODE + 0x40000)   # code buffer is reused: drop stale JIT blocks
    mu.mem_write(CODE, code + b"\xcc" * 16)
    sp = STK + 0x30000
    mu.mem_write(sp, struct.pack("<Q", RET))
    mu.reg_write(UC_X86_REG_RSP, sp)
    mu.reg_write(UC_X86_REG_RCX, rcx); mu.reg_write(UC_X86_REG_RDX, rdx)
    mu.reg_write(UC_X86_REG_R8, r8);   mu.reg_write(UC_X86_REG_R9, 0)
    mu.emu_start(CODE, RET)
    return mu.reg_read(UC_X86_REG_RAX) & 0xFFFFFFFF

def run_node(code, state, ch):
    mu.mem_write(DATA, state)
    nxt = call(code, ch, DATA)
    return nxt, bytes(mu.mem_read(DATA, 32))

_cache = {}
def step(recs, node, state, ch):
    """node(ch, state) -> (next_node, new_state). Mirrors the 0x113AE call at 0x86C5."""
    if node not in _cache:
        raw = decrypt_record(recs, node)
        fast = skip_padding(raw)
        probe = bytes(range(32))
        # keep the shortcut only if it agrees with the original code on two probes
        ok = all(run_node(fast, probe, c) == run_node(raw, probe, c) for c in (0x41, 0x7A))
        _cache[node] = fast if ok else raw
    mu.mem_write(DATA, state)
    nxt = call(_cache[node], ch, DATA)
    return nxt, bytes(mu.mem_read(DATA, 32))

def find_password(recs):
    # Depth-first search over printable characters. A wrong character returns an
    # id that is not a record (dead end) or wanders into a short blind alley.
    path = []
    def dfs(node, state):
        for ch in range(0x20, 0x7F):
            nxt, st = step(recs, node, state, ch)
            if nxt == ACCEPT_NODE:
                path.append(ch); return st
            if nxt in recs:
                path.append(ch)
                res = dfs(nxt, st)
                if res is not None:
                    return res
                path.pop()
        return None
    state = dfs(START_NODE, bytes(32))
    return bytes(path), state

# ---------- 5. decrypt the flag ----------
def decrypt_flag(recs, key32):
    xtea = decrypt_record(recs, ACCEPT_NODE)   # record 0x1185 is an XTEA routine
    ct = decrypt_record(recs, FLAG_CT)         # record 0x2706 is the 40-byte ciphertext
    out, ctp, keyp = DATA, DATA + 0x1000, DATA + 0x2000
    mu.mem_write(out, bytes(64)); mu.mem_write(ctp, ct); mu.mem_write(keyp, key32)
    call(xtea, out, ctp, keyp)
    return bytes(mu.mem_read(out, 64)).split(b"\0")[0]

def main():
    exe = open(sys.argv[1] if len(sys.argv) > 1 else "FlareCalc.exe", "rb").read()
    recs = parse_records(carve_payload(exe))
    print(f"[+] records under OID 1.3.6.1.4.1.1337.1 : {len(recs)}")
    print(f"[+] PRNG seed of '{KEYSTR.decode()}' : {SEED:#010x}")
    t = time.time()
    pw, key = find_password(recs)
    print(f"[+] password  : {pw.decode()}   ({time.time() - t:.1f}s)")
    print(f"[+] XTEA key  : {key.hex()}")
    print(f"[+] FLAG      : {decrypt_flag(recs, key).decode()}")

if __name__ == "__main__":
    main()
