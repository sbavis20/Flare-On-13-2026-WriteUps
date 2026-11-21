#!/usr/bin/env python3
"""
Flare-On 13 (2026) - Challenge 6: Threat Invaders
Replays the attacker's session from challenge.pcapng and decrypts it.

Standard library only. Usage:  python solve.py challenge.pcapng
"""
import base64
import json
import re
import struct
import sys
import uuid

M64 = (1 << 64) - 1


# ---------------------------------------------------------------- pcapng / TCP

def read_tcp_streams(path):
    """Return {(src, sport, dst, dport): bytes} for an Ethernet pcapng."""
    data = open(path, "rb").read()
    segs = {}
    off = 0
    while off + 12 <= len(data):
        btype, blen = struct.unpack_from("<II", data, off)
        if btype == 6:  # Enhanced Packet Block
            caplen = struct.unpack_from("<I", data, off + 20)[0]
            pkt = data[off + 28: off + 28 + caplen]
            if len(pkt) > 34 and pkt[12:14] == b"\x08\x00" and pkt[23] == 6:
                ihl = (pkt[14] & 0x0F) * 4
                tot = struct.unpack_from(">H", pkt, 16)[0]
                src, dst = pkt[26:30], pkt[30:34]
                t = 14 + ihl
                sport, dport, seq = struct.unpack_from(">HHI", pkt, t)
                thl = (pkt[t + 12] >> 4) * 4
                end = 14 + tot if tot else len(pkt)  # tot == 0 on offloaded (TSO) packets
                payload = pkt[t + thl: end]
                if payload:
                    key = (src, sport, dst, dport)
                    segs.setdefault(key, {})[seq] = payload
        off += blen
    return {k: b"".join(v[s] for s in sorted(v)) for k, v in segs.items()}


def http_exchanges(path):
    """Pair each HTTP request with its response, in order."""
    streams = read_tcp_streams(path)
    req = next(v for k, v in streams.items() if k[3] == 80)
    rsp = next(v for k, v in streams.items() if k[1] == 80)
    reqs = [p for p in re.split(rb"(?=(?:GET|POST) /api)", req) if p.strip()]
    rsps = [p for p in re.split(rb"(?=HTTP/1\.1 \d{3} )", rsp) if p.strip()]
    for q, r in zip(reqs, rsps):
        q_head, _, q_body = q.partition(b"\r\n\r\n")
        r_head, _, r_body = r.partition(b"\r\n\r\n")
        line = q_head.split(b"\r\n")[0].decode()
        status = int(r_head.split(b" ")[1])
        yield line, q_body, status, r_body


# ---------------------------------------------------------- backdoor cipher
# FUN_1400c65e0: seed once from the 16-byte MachineGuid, then a 64-bit LCG
# whose top byte is XORed onto the data. One global state, never reset.

def seed(key16):
    a, b = struct.unpack("<QQ", key16)
    x = a ^ (((a >> 2) + 0x9E3779B97F4A7C15 + ((a << 6) & M64) + b) & M64)
    x = ((x >> 33 ^ x) * 0xFF51AFD7ED558CCD) & M64
    x = ((x >> 29 ^ x) * 0xC4CEB9FE1A85EC53) & M64
    return (x >> 32) ^ x


class Keystream:
    def __init__(self, key16):
        self.state = seed(key16)

    def crypt(self, data):
        out = bytearray()
        for byte in data:
            self.state = (self.state * 0x5851F42D4C957F2D + 0x14057B7EF767814F) & M64
            out.append(byte ^ (self.state >> 56))
        return bytes(out)


# ------------------------------------------------------------- triggers

def name_xor_score(entry):
    """FUN_1400c66f0: first 4 bytes of PlayerName XOR Score must read 'cmd:'."""
    name4 = entry["player_name"].upper().encode()[:4].ljust(4, b"\0")
    tag = struct.unpack("<I", name4)[0] ^ (entry["score"] & 0xFFFFFFFF)
    return struct.pack("<I", tag)


def main(pcap):
    session_id = None
    stream = None
    print(f"[*] parsing {pcap}\n")

    for line, q_body, status, r_body in http_exchanges(pcap):
        # Telemetry upload: feedback_length carries flags set by the hook
        #   0x2000 | 16  -> MachineGuid XOR reversed(SessionId)
        #   0x4000 | n   -> n bytes of encrypted command output
        if line.startswith("POST /api/v1/telemetry"):
            doc = json.loads(q_body)
            session_id = doc["session_id"]
            flags, length = doc["feedback_length"] & 0xF000, doc["feedback_length"] & 0x0FFF
            raw = base64.b64decode(doc["feedback_b64"]) if doc["feedback_b64"] else b""

            if flags == 0x2000:
                sess = uuid.UUID(session_id).bytes_le          # in-memory Guid layout
                key = bytes(raw[i] ^ sess[15 - i] for i in range(16))
                stream = Keystream(key)
                print(f"[+] key leak in telemetry   session  {session_id}")
                print(f"    MachineGuid bytes   {key.hex(' ')}")
                print(f"    MachineGuid         {uuid.UUID(bytes_le=key)}\n")
            elif flags == 0x4000 and stream:
                out = stream.crypt(raw[:length]).decode(errors="replace")
                print(f"[+] command output ({length} bytes)")
                print("    " + out.strip().replace("\r\n", "\n    ") + "\n")

        # Board download: the replaced ReplaceHighscores decrypts every
        # cmd-tagged comment it sees, advancing the shared keystream.
        elif line.startswith("GET /api/v1/highscores") and status == 200 and stream:
            for e in json.loads(r_body)["entries"]:
                if name_xor_score(e) == b"cmd:":
                    pt = stream.crypt(base64.b64decode(e["comment_b64"]))
                    path, args = pt[4:].split(b";")[:2]
                    print(f"[+] command from board entry {e['player_name']!r} (score {e['score']})")
                    print(f"    {pt!r}  ->  {path.decode()} {args.decode()}\n")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "challenge.pcapng")
