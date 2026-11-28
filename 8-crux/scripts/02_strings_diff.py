#!/usr/bin/env python3
"""Stage 2: which strings appear in Go memory during ONE check() call?

usage: node harness.js <chal> <input> --dump run   (creates run.before.bin / run.after.bin)
       python3 02_strings_diff.py run
"""
import sys
a = open(sys.argv[1] + '.before.bin', 'rb').read()
b = open(sys.argv[1] + '.after.bin', 'rb').read()
i = 0
while i < len(b):
    if i < len(a) and a[i] == b[i]:
        i += 1; continue
    j = i
    while j < len(b) and 0x20 <= b[j] < 0x7f:
        j += 1
    if j - i >= 8:
        print(f'0x{i:06x}  {b[i:j].decode()}')
        i = j
    else:
        i += 1
