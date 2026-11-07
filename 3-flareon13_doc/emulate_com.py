# emulate_com.py - run the 16-bit DOS stub at byte 0 of flareon13.doc and print what it outputs
# pip install unicorn
import sys
from unicorn import Uc, UC_ARCH_X86, UC_MODE_16, UC_HOOK_INTR
from unicorn.x86_const import *

data = open(sys.argv[1] if len(sys.argv) > 1 else "flareon13.doc", "rb").read()
SEG = 0x1000
BASE = SEG * 16
mu = Uc(UC_ARCH_X86, UC_MODE_16)
mu.mem_map(0, 0x30000)
mu.mem_write(BASE + 0x100, data[:0xff00])   # a .COM file loads at offset 0x100
for r in (UC_X86_REG_CS, UC_X86_REG_DS, UC_X86_REG_ES, UC_X86_REG_SS):
    mu.reg_write(r, SEG)
mu.reg_write(UC_X86_REG_SP, 0xfffe)

def on_int(uc, num, _):
    ah = uc.reg_read(UC_X86_REG_AH)
    if num == 0x21 and ah == 0x09:          # print '$'-terminated string at DS:DX
        dx = uc.reg_read(UC_X86_REG_DX)
        print(bytes(uc.mem_read(BASE + dx, 200)).split(b"$")[0].decode())
    if num == 0x20 or (num == 0x21 and ah == 0x4c):
        uc.emu_stop()

mu.hook_add(UC_HOOK_INTR, on_int)
mu.emu_start(BASE + 0x100, BASE + 0xffff, count=100000)
