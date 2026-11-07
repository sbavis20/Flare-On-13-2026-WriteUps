# emulate_decoy.py - run slice0_arm64.bin (the Odin "decoy") without a Mac and show its screen output
# pip install unicorn
# The slice only imports bzero, memcpy, memmove, ptrace, usleep, write and __tlv_bootstrap,
# so each import is replaced by a tiny Python handler.
import re
import struct
import sys
from unicorn import Uc, UcError, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm64_const import *

path = sys.argv[1] if len(sys.argv) > 1 else "slice0_arm64.bin"
frames = int(sys.argv[2]) if len(sys.argv) > 2 else 20
d = open(path, "rb").read()

mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
BASE = 0x100000000
mu.mem_map(BASE, 0x14000)
mu.mem_write(BASE, d[:0xc000])               # __TEXT, __DATA_CONST, __DATA
mu.mem_write(0x100008000, struct.pack("<Q", 0x1000012a8))   # rebase the two pointers in __data
mu.mem_write(0x100008010, struct.pack("<Q", 0x1000012de))

STUB = 0x200000000
mu.mem_map(STUB, 0x1000)
names = ["bzero", "memcpy", "memmove", "ptrace", "usleep", "write", "tlv"]
for i in range(len(names)):
    mu.mem_write(STUB + i * 4, b"\xc0\x03\x5f\xd6")           # ret
for i in range(6):
    mu.mem_write(0x100004000 + i * 8, struct.pack("<Q", STUB + i * 4))   # __got
mu.mem_write(0x100008028, struct.pack("<Q", STUB + 24))     # __thread_vars thunk

TLS = 0x300000000
mu.mem_map(TLS, 0x10000)
STACK = 0x400000000
mu.mem_map(STACK, 0x100000)
mu.reg_write(UC_ARM64_REG_SP, STACK + 0xf0000)

out = bytearray()
sleeps = [0]

def on_import(uc, addr, size, _):
    name = names[(addr - STUB) // 4]
    x0, x1, x2 = (uc.reg_read(r) for r in (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2))
    if name == "bzero":
        uc.mem_write(x0, b"\0" * x1)
    elif name in ("memcpy", "memmove"):
        uc.mem_write(x0, bytes(uc.mem_read(x1, x2)))
    elif name == "ptrace":                   # PT_DENY_ATTACH anti-debug, just say OK
        uc.reg_write(UC_ARM64_REG_X0, 0)
    elif name == "usleep":                   # one sleep per animation frame
        sleeps[0] += 1
        if sleeps[0] >= frames:
            uc.emu_stop()
    elif name == "write":
        out.extend(uc.mem_read(x1, x2))
        uc.reg_write(UC_ARM64_REG_X0, x2)
    elif name == "tlv":
        uc.reg_write(UC_ARM64_REG_X0, TLS + struct.unpack("<Q", uc.mem_read(x0 + 16, 8))[0])

mu.hook_add(UC_HOOK_CODE, on_import, begin=STUB, end=STUB + 0x100)
mu.reg_write(UC_ARM64_REG_LR, STUB + 0x800)
try:
    mu.emu_start(0x1000006b4, STUB + 0x800, count=300_000_000)
except UcError:
    pass

last = out.decode("utf-8", "replace").split("\x1b[H")[-1]
plain = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", last)
print("\n".join(l for l in plain.split("\n") if l.strip()))
