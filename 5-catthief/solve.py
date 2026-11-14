"""
Flare-On 13 - Challenge 5: catthief
Recovers the files exfiltrated by catthief.exe from capture.pcapng.
No third-party dependencies: parses pcapng, reassembles TCP, RC4-decrypts
and canonical-Huffman-decodes each /exfil upload.

usage: python solve.py capture.pcapng [outdir]
"""
import os
import struct
import sys
from collections import defaultdict

KEY = b"i11_b3_p1und3r1n_y3r_d474"   # 25 bytes, stored in the binary XORed with 0x33
C2_PORT = 8080


def rc4(key, data):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray()
    for c in data:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out.append(c ^ S[(S[i] + S[j]) & 0xFF])
    return bytes(out)


def huffman_decode(buf):
    # Bitstream, MSB first:
    #   11 bits  number of symbols in table (256)
    #   32 bits  length of the encoded data in bytes
    #   8 bits * N  code length for each byte value
    #   data     canonical Huffman codes
    bits = "".join(f"{b:08b}" for b in buf)
    pos = 0

    def take(n):
        nonlocal pos
        v = int(bits[pos:pos + n], 2)
        pos += n
        return v

    nsym = take(11)
    dlen = take(32)
    lengths = [take(8) for _ in range(nsym)]

    # canonical code assignment, sorted by (length, symbol)
    pairs = sorted((l, s) for s, l in enumerate(lengths) if l)
    table = {}
    code = 0
    prev = pairs[0][0]
    for k, (l, s) in enumerate(pairs):
        if k:
            code = (code + 1) << (l - prev)
        prev = l
        table[f"{code:0{l}b}"] = s

    out = bytearray()
    cur = ""
    for b in bits[pos:pos + dlen * 8]:
        cur += b
        if cur in table:
            out.append(table[cur])
            cur = ""
    return bytes(out)


def read_tcp_streams(path):
    """Return {(client_port, direction): bytes} for TCP traffic on C2_PORT."""
    segs = defaultdict(dict)
    data = open(path, "rb").read()
    off = 0
    endian = "<"
    while off + 8 <= len(data):
        btype, blen = struct.unpack_from(endian + "II", data, off)
        if btype == 0x0A0D0D0A:  # section header: detect byte order
            endian = "<" if data[off + 8:off + 12] == b"\x4d\x3c\x2b\x1a" else ">"
            blen = struct.unpack_from(endian + "I", data, off + 4)[0]
        elif btype == 6:  # enhanced packet block
            caplen = struct.unpack_from(endian + "I", data, off + 20)[0]
            pkt = data[off + 28:off + 28 + caplen]
            if len(pkt) > 34 and pkt[12:14] == b"\x08\x00" and pkt[23] == 6:
                ihl = (pkt[14] & 0x0F) * 4
                tcp = 14 + ihl
                total = struct.unpack(">H", pkt[16:18])[0]
                sport, dport, seq = struct.unpack(">HHI", pkt[tcp:tcp + 8])
                doff = (pkt[tcp + 12] >> 4) * 4
                payload = pkt[tcp + doff:14 + total]
                if payload:
                    if dport == C2_PORT:
                        segs[(sport, "up")][seq] = payload
                    elif sport == C2_PORT:
                        segs[(dport, "down")][seq] = payload
        off += blen
    return {k: b"".join(v[s] for s in sorted(v)) for k, v in segs.items()}


def http_body(raw):
    return raw.partition(b"\r\n\r\n")[2]


def main():
    pcap = sys.argv[1] if len(sys.argv) > 1 else "capture.pcapng"
    outdir = sys.argv[2] if len(sys.argv) > 2 else "recovered"
    os.makedirs(outdir, exist_ok=True)

    streams = read_tcp_streams(pcap)
    ports = sorted({p for p, _ in streams})

    # Each server reply names the file the client must upload on its NEXT request.
    requested = None
    for port in ports:
        up = http_body(streams.get((port, "up"), b""))
        down = http_body(streams.get((port, "down"), b""))

        plain = huffman_decode(rc4(KEY, up))
        if requested is None:
            print(f"[{port}] client -> {plain[:5]!r}")
        else:
            end = plain.rfind(b"\xff\xd9")      # drop padding-bit junk after JPEG EOI
            if end != -1:
                plain = plain[:end + 2]
            name = requested.split("\\")[-1]
            open(os.path.join(outdir, name), "wb").write(plain)
            print(f"[{port}] client -> {name} ({len(plain)} bytes)")

        if down:
            requested = rc4(KEY, down).decode()
            print(f"[{port}] server -> {requested}")


if __name__ == "__main__":
    main()
