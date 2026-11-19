#!/usr/bin/env python3
"""Build ENS DNSSEC SignedSet fixtures for NSEC3 denial-of-existence proofs.

The sibling of mkfixture.py. That tool reads the root zone, which is NSEC.
This one reads a TLD's own zone, which is almost always NSEC3, and captures the
denial of `_ens.<tld>`.

Census of 19 Nov 2026 (survey/NSEC3-CENSUS-2026-11-19.md): 1308 of 1436 TLDs in
the root use NSEC3, every EBERO TLD does, no TLD sets the opt-out flag, and the
highest iteration count in the root is 20.

Format is identical to mkfixture.py's: RRSIG rdata header through signerName,
then each covered RR in RFC 4035 canonical form with the TTL replaced by the
RRSIG original TTL. NSEC3 rdata holds no domain name, so the rdata needs no
decompression and is canonical as received.
"""
import socket
import struct
import sys
from mkfixture import read_name, parse, build, encode_name, wire_to_str, decode_bitmap

ROOT_A = "198.41.0.4"
T_NS, T_A, T_TXT, T_RRSIG, T_NSEC3, T_SOA = 2, 1, 16, 46, 50, 6
B32HEX = "0123456789abcdefghijklmnopqrstuv"


def ask(name, qtype, server, tcp=False):
    """One query with the DO bit set. Falls back to TCP when truncated."""
    header = struct.pack(">HHHHHH", 0x1234, 0x0000, 1, 0, 0, 1)   # no RD
    q = encode_name(name) + struct.pack(">HH", qtype, 1)
    opt = b"\x00" + struct.pack(">HHIH", 41, 4096, 0x00008000, 0)
    pkt = header + q + opt
    if tcp:
        s = socket.create_connection((server, 53), timeout=10)
        s.sendall(struct.pack(">H", len(pkt)) + pkt)
        ln = struct.unpack(">H", s.recv(2))[0]
        buf = b""
        while len(buf) < ln:
            buf += s.recv(ln - len(buf))
        s.close()
        return buf
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(10)
    s.sendto(pkt, (server, 53))
    data, _ = s.recvfrom(65535)
    s.close()
    if struct.unpack(">H", data[2:4])[0] & 0x0200:          # TC
        return ask(name, qtype, server, tcp=True)
    return data


def authoritative_ips(tld):
    """Glue addresses for a TLD, from the root's referral."""
    rrs = parse(ask(tld + ".", T_NS, ROOT_A))
    ips = [socket.inet_ntoa(r["rdata"]) for r in rrs
           if r["type"] == T_A and r["section"] == "ar" and len(r["rdata"]) == 4]
    if ips:
        return ips
    names = [wire_to_str(read_name(r["raw"], r["rdata_off"])[0]) for r in rrs
             if r["type"] == T_NS]
    out = []
    for n in names:
        try:
            out.append(socket.gethostbyname(n.rstrip(".")))
        except OSError:
            pass
    return out


def nsec3param(tld, ip):
    rrs = parse(ask(tld + ".", 51, ip))
    for r in rrs:
        if r["type"] == 51:
            alg, flags, iters, saltlen = struct.unpack(">BBHB", r["rdata"][:5])
            return alg, flags, iters, r["rdata"][5:5 + saltlen]
    return None


def b32hex_label(owner_wire):
    """The first label of an NSEC3 owner name, as its decoded 20 byte hash."""
    ln = owner_wire[0]
    lab = owner_wire[1:1 + ln].decode("ascii").lower()
    bits = "".join(f"{B32HEX.index(c):05b}" for c in lab)
    return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits) - 7, 8))


def fixture(tld, qname=None):
    qname = qname or f"_ens.{tld}"
    ips = authoritative_ips(tld)
    if not ips:
        print(f"[{tld}] no authoritative address found")
        return
    ip = ips[0]
    p = nsec3param(tld, ip)
    data = parse(ask(qname + ".", T_TXT, ip))
    n3 = [r for r in data if r["type"] == T_NSEC3]
    rcode = "NXDOMAIN" if struct.unpack(">H", ask(qname + ".", T_TXT, ip)[2:4])[0] & 0xF == 3 else "NOERROR"
    print(f"\n=== {tld}  via {ip}  query={qname} TXT  rcode={rcode}")
    if p:
        print(f"    NSEC3PARAM alg={p[0]} flags={p[1]} iterations={p[2]} "
              f"salt={p[3].hex() if p[3] else '-'}")
    if not n3:
        print("    no NSEC3 records in the authority section")
        return
    print(f"    {len(n3)} NSEC3 record(s)")
    for r in n3:
        sigs = [s for s in data if s["type"] == T_RRSIG and s["owner"] == r["owner"]
                and struct.unpack(">H", s["rdata"][:2])[0] == T_NSEC3]
        if not sigs:
            print("    (no RRSIG for this record, skipped)")
            continue
        blob, signature, meta = build([r], sigs[0], lambda rr: rr["rdata"])
        alg, flags, iters, saltlen = struct.unpack(">BBHB", r["rdata"][:5])
        salt = r["rdata"][5:5 + saltlen]
        o = 5 + saltlen
        hashlen = r["rdata"][o]
        nexthash = r["rdata"][o + 1:o + 1 + hashlen]
        bitmap = r["rdata"][o + 1 + hashlen:]
        print(f"    owner      = {wire_to_str(r['owner'])}")
        print(f"    ownerhash  = {b32hex_label(r['owner']).hex()}")
        print(f"    nexthash   = {nexthash.hex()}")
        print(f"    flags={flags} iterations={iters} salt={salt.hex() if salt else '-'} hashlen={hashlen}")
        print(f"    bitmap     = {bitmap.hex()}  types={decode_bitmap(bitmap)}")
        print(f"    inception  = {meta['inception']}  expiration = {meta['expiration']}  keytag={meta['keytag']}")
        print(f"    rrset      = {blob.hex()}")
        print(f"    sig        = {signature.hex()}")


if __name__ == "__main__":
    targets = sys.argv[1:] or ["desi", "nowruz", "firmdale", "bn"]
    for t in targets:
        try:
            fixture(t)
        except Exception as e:
            print(f"[{t}] {type(e).__name__}: {e}")
