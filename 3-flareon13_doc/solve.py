# solve.py - Flare-On 13, challenge 3 (flareon13.doc)
# Rebuilds the check from slice1 (the Crystal binary) and decrypts the flag offline.
import hashlib
import struct

# The six input lines, one hidden in each part of the polyglot
lines = [
    "FLARE-STANDARD-ANTIVIRUS-TEST-FILE!",  # DOS stub output (emulate_com.py)
    "mainframe_ebcdic_ghost",               # PDF invisible text, EBCDIC
    "jbig2_fax_geometry",                   # PDF JBIG2 image
    "udf_tagged_descriptor",                # UDF disc metadata
    "reduce_not_deflate",                   # ZIP flag.txt, password "infected"
    "Ød1n_373rn4l_fl4r3",              # decoy slice runtime output (emulate_decoy.py)
]

# Six 32-byte blocks stored in crystal_main as 8-byte immediates.
# Each byte is 0x80 | index into "0123456789abcdefghijklmnopqrstuvwxyz".
blocks = [
    [0x8b8a80888182888d, 0x888c888e86888987, 0x8f80808f8e868882, 0x85888884808c8681],
    [0x8a838a8c8c858585, 0x8d8b87858f848683, 0x87888e8085858e84, 0x8d88808c818f8885],
    [0x84878b8c8089878c, 0x8f848a86878c8d8d, 0x878f898c83888f89, 0x8c8f868d82888889],
    [0x8b818d8b8c808f8c, 0x81888a8585878585, 0x8e8b828f87888f8f, 0x8f8b8e888a8b8f88],
    [0x89848b8d8080848d, 0x828f8b8e81838c83, 0x848a828b808a8f81, 0x8087808e8a8e8d8a],
    [0x88818e8d818c8f89, 0x8885818687828e83, 0x8780898e8c8f8d85, 0x8c8d8984828a8f8a],
]
alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
targets = []
for b in blocks:
    raw = b"".join(struct.pack("<Q", q) for q in b)
    targets.append("".join(alphabet[x & 0x7f] for x in raw))

# Check 1: the set of MD5(line) must equal the set of targets (order does not matter)
got = [hashlib.md5(l.encode()).hexdigest() for l in lines]
for l, h in zip(lines, got):
    print(("OK  " if h in targets else "BAD ") + h + "  " + l)
assert sorted(got) == sorted(targets)

# Check 2: key = XOR of SHA-256(line) for all six lines
key = bytearray(32)
for l in lines:
    key = bytearray(a ^ b for a, b in zip(key, hashlib.sha256(l.encode()).digest()))

# 80 obfuscated bytes, packed two nibbles per byte -> 40-byte RC4 ciphertext
ct_words = [0x8180888281858486, 0x8e80858789868783, 0x81898f8185848085, 0x8389848f88858587,
            0x8a858d8e8e8a838e, 0x8a8f8b8c808d8185, 0x88818d8e8e88898e, 0x808b80808b818e85,
            0x8381888f888a8284, 0x8c818585858d898a]
raw = b"".join(struct.pack("<Q", q) for q in ct_words)
ct = bytes(((raw[i] & 0xf) << 4) | (raw[i + 1] & 0xf) for i in range(0, len(raw), 2))

# Plain RC4
S = list(range(256))
j = 0
for i in range(256):
    j = (j + S[i] + key[i % len(key)]) & 0xff
    S[i], S[j] = S[j], S[i]
i = j = 0
out = bytearray()
for c in ct:
    i = (i + 1) & 0xff
    j = (j + S[i]) & 0xff
    S[i], S[j] = S[j], S[i]
    out.append(c ^ S[(S[i] + S[j]) & 0xff])
print("Flag:", out.decode())
