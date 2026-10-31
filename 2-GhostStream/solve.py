ads = b"AlbusDumbledore \r\n"   # PolyjuicePotion.txt:LordVoldemort
xor_key = bytes.fromhex("8b8f92858896989b948b95e6edf0e7")
ct = bytes.fromhex("965c8735d77a398b75046d28bb5658c8"
                   "35eedae1a456a937811556f9270a340d"
                   "ee822c26a5f8")
k2 = b"Piertotum Locomotor"
stride = len(b"Wingardium Leviosa")  # 18

# GhostStream WM_CREATE transform: XOR 0x82, then first 15 bytes with xor_key
buf = bytearray(b ^ 0x82 for b in ads)
for i in range(15):
    buf[i] ^= xor_key[i]
key = bytes(buf).split(b"\r")[0].split(b"\n")[0]
print("Pipe key:", key)

# Partner_CTF: RC4 KSA, then modified PRGA
S = list(range(256))
j = 0
for i in range(256):
    j = (j + S[i] + key[i % len(key)]) & 0xff
    S[i], S[j] = S[j], S[i]

i = j = 0
out = bytearray()
for n, c in enumerate(ct):
    i = (i + stride) & 0xff
    j = (j + S[i]) & 0xff
    S[i], S[j] = S[j], S[i]
    out.append(S[(S[i] + S[j]) & 0xff] ^ k2[n % len(k2)] ^ ((c + stride) & 0xff))
print("Flag:", out.decode())
