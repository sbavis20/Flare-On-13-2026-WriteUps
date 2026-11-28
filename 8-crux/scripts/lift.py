#!/usr/bin/env python3
"""Tiny stack-to-statement lifter for Go/wasm functions (wasm2wat text in, pseudo-code out).
Good enough to read Go's br_table state machines; not a decompiler.
usage: python3 lift.py func.wat names.json > func.txt
"""
import re, sys, json
names = json.load(open(sys.argv[2]))
nm = lambda i: names.get(str(i), f'f{i}') or f'f{i}'
BIN = {'add':'+','sub':'-','mul':'*','and':'&','or':'|','xor':'^','shl':'<<','shr_u':'>>','shr_s':'>>s',
       'eq':'==','ne':'!=','lt_s':'<','lt_u':'<u','gt_s':'>','gt_u':'>u','le_s':'<=','le_u':'<=u',
       'ge_s':'>=','ge_u':'>=u','div_u':'/','div_s':'/s','rem_u':'%','rem_s':'%s'}
st, out = [], []
pop = lambda: st.pop() if st else '?'
for l in open(sys.argv[1]):
    l = l.strip().rstrip(')'); t = l.split()
    if not t: continue
    op = t[0]; m = re.match(r'(i32|i64)\.(\w+)', op)
    if op == 'local.get': st.append('SP' if t[1] == '1' else f'L{t[1]}')
    elif op == 'global.get': st.append('g')
    elif op in ('local.set', 'local.tee'):
        v = pop()
        if t[1] != '1': out.append(f'L{t[1]} = {v}')
        if op == 'local.tee': st.append('SP' if t[1] == '1' else f'L{t[1]}')
    elif op == 'global.set': pop()
    elif m and m.group(2) == 'const': v = int(t[1]); st.append(hex(v) if abs(v) > 9 else str(v))
    elif m and m.group(2).startswith('load'):
        a = pop(); o = next((x[7:] for x in t if x.startswith('offset=')), '0')
        st.append(f'[{a}+{o}]{m.group(2)[4:]}'.replace('+0]', ']'))
    elif m and m.group(2).startswith('store'):
        v = pop(); a = pop(); o = next((x[7:] for x in t if x.startswith('offset=')), '0')
        out.append(f'[{a}+{o}]{m.group(2)[5:]} = {v}'.replace('+0]', ']'))
    elif m and m.group(2) in ('wrap_i64', 'extend_i32_u', 'extend_i32_s'): pass
    elif m and m.group(2) == 'eqz': st.append(f'!({pop()})')
    elif m and m.group(2) in BIN: b = pop(); a = pop(); st.append(f'({a} {BIN[m.group(2)]} {b})')
    elif op == 'call':
        if t[1] != '1348': pop(); out.append(f'CALL {nm(int(t[1]))}')
        st.append('ret')
    elif op == 'if': out.append(f'if {pop()}:')
    elif op == 'br_if': c = pop(); c != 'ret' and out.append(f'br_if {c}')
    elif op == 'return': pop(); out.append('RETURN')
    elif op == 'unreachable': out.append('UNREACHABLE')
    elif op == 'drop': pop()
txt = '\n'.join(out)
txt = re.sub(r'\(SP \+ (\w+)\)', r'SP+\1', txt)
txt = re.sub(r'L0 = (\w+)\n', r'goto state_\1\n', txt)
print('\n'.join(x for x in txt.split('\n') if not x.startswith('[SP] = 0x1c') and 'SP <=u' not in x))
