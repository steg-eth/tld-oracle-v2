#!/usr/bin/env python3
"""Build ENS DNSSEC SignedSet fixtures from live root-server answers.

ENS's RRSetWithSignature.rrset is the RRSIG rdata header through signerName,
followed by each covered RR in RFC 4035 canonical form, with the TTL replaced
by the RRSIG's original TTL. .signature is the RRSIG signature field.

Verified against the known-good fixture in RootProof.t.sol:
  002f 08 01 00015180 6b0519d0 6af3e840 223b 00
  | 07646f6d61696e7300 002f 0001 00015180 000d 03646f7400 0006200000000013
"""
import socket
import struct
import sys

ROOT_A = "198.41.0.4"
TYPE = {"NSEC": 47, "DS": 43, "DNSKEY": 48, "RRSIG": 46, "NS": 2, "SOA": 6}


def encode_name(name):
    out = b""
    for label in name.rstrip(".").split("."):
        if label:
            out += bytes([len(label)]) + label.encode("ascii").lower()
    return out + b"\x00"


def query(name, qtype, server=ROOT_A):
    qid = 0x1234
    header = struct.pack(">HHHHHH", qid, 0x0000, 1, 0, 0, 1)   # no RD
    q = encode_name(name) + struct.pack(">HH", TYPE[qtype], 1)
    # EDNS0 OPT with DO bit set, 4096 udp payload
    opt = b"\x00" + struct.pack(">HHIH", 41, 4096, 0x00008000, 0)
    pkt = header + q + opt
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(10)
    s.sendto(pkt, (server, 53))
    data, _ = s.recvfrom(65535)
    s.close()
    return data


def read_name(data, off):
    """Return (uncompressed lowercase wire name, new offset)."""
    out = b""
    jumped = False
    end = off
    while True:
        ln = data[off]
        if ln == 0:
            out += b"\x00"
            off += 1
            if not jumped:
                end = off
            break
        if ln & 0xC0 == 0xC0:
            ptr = struct.unpack(">H", data[off:off + 2])[0] & 0x3FFF
            if not jumped:
                end = off + 2
            off = ptr
            jumped = True
            continue
        out += data[off:off + 1 + ln].lower()
        off += 1 + ln
        if not jumped:
            end = off
    return out, end


def parse(data):
    qd, an, ns, ar = struct.unpack(">HHHH", data[4:12])
    off = 12
    for _ in range(qd):
        _, off = read_name(data, off)
        off += 4
    rrs = []
    for section, count in (("an", an), ("ns", ns), ("ar", ar)):
        for _ in range(count):
            owner, off = read_name(data, off)
            rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
            off += 10
            rdata = data[off:off + rdlen]
            rdata_off = off
            off += rdlen
            rrs.append({"section": section, "owner": owner, "type": rtype,
                        "class": rclass, "ttl": ttl, "rdata": rdata,
                        "rdata_off": rdata_off, "raw": data})
    return rrs


def canon_nsec_rdata(rr):
    """NSEC rdata with the next-owner name uncompressed and lowercased."""
    nxt, end = read_name(rr["raw"], rr["rdata_off"])
    bitmap = rr["raw"][end:rr["rdata_off"] + len(rr["rdata"])]
    return nxt + bitmap


def build(rrset_rrs, rrsig, canon_rdata):
    """ENS SignedSet blob + signature bytes."""
    sig = rrsig["rdata"]
    typecovered, alg, labels, origttl, expiration, inception, keytag = \
        struct.unpack(">HBBIIIH", sig[:18])
    signer, soff = read_name(rrsig["raw"], rrsig["rdata_off"] + 18)
    signature = sig[18 + (soff - (rrsig["rdata_off"] + 18)):]
    head = struct.pack(">HBBIIIH", typecovered, alg, labels, origttl,
                       expiration, inception, keytag) + signer
    body = b""
    for rr in sorted(rrset_rrs, key=lambda r: r["owner"]):
        rd = canon_rdata(rr)
        body += rr["owner"] + struct.pack(">HHIH", rr["type"], rr["class"],
                                          origttl, len(rd)) + rd
    return head + body, signature, {
        "typecovered": typecovered, "alg": alg, "labels": labels,
        "origttl": origttl, "expiration": expiration, "inception": inception,
        "keytag": keytag}


def fixture(qname, label):
    data = query(qname, "DS")
    rrs = parse(data)
    nsecs = [r for r in rrs if r["type"] == TYPE["NSEC"]]
    if not nsecs:
        print(f"[{label}] no NSEC returned for {qname}")
        return None
    out = []
    for nsec in nsecs:
        sigs = [r for r in rrs if r["type"] == TYPE["RRSIG"]
                and r["owner"] == nsec["owner"]
                and struct.unpack(">H", r["rdata"][:2])[0] == TYPE["NSEC"]]
        if not sigs:
            continue
        blob, signature, meta = build([nsec], sigs[0], canon_nsec_rdata)
        nxt, end = read_name(nsec["raw"], nsec["rdata_off"])
        bitmap = nsec["raw"][end:nsec["rdata_off"] + len(nsec["rdata"])]
        print(f"\n[{label}] query={qname} owner={nsec['owner'].hex()} "
              f"next={nxt.hex()} keytag={meta['keytag']} "
              f"exp={meta['expiration']} inc={meta['inception']}")
        print(f"  owner  = {wire_to_str(nsec['owner'])}")
        print(f"  next   = {wire_to_str(nxt)}")
        print(f"  bitmap = {bitmap.hex()}  types={decode_bitmap(bitmap)}")
        print(f"  rrset  = {blob.hex()}")
        print(f"  sig    = {signature.hex()}")
        out.append((blob, signature))
    return out


def wire_to_str(w):
    parts = []
    i = 0
    while i < len(w) and w[i]:
        ln = w[i]
        parts.append(w[i + 1:i + 1 + ln].decode("ascii"))
        i += 1 + ln
    return (".".join(parts) + ".") if parts else "."


def decode_bitmap(bm):
    names = {1: "A", 2: "NS", 6: "SOA", 15: "MX", 16: "TXT", 28: "AAAA",
             43: "DS", 46: "RRSIG", 47: "NSEC", 48: "DNSKEY", 50: "NSEC3",
             51: "NSEC3PARAM", 65534: "?"}
    out = []
    i = 0
    while i + 1 < len(bm):
        window, ln = bm[i], bm[i + 1]
        block = bm[i + 2:i + 2 + ln]
        for bi, byte in enumerate(block):
            for bit in range(8):
                if byte & (0x80 >> bit):
                    t = window * 256 + bi * 8 + bit
                    out.append(names.get(t, str(t)))
        i += 2 + ln
    return " ".join(out)


if __name__ == "__main__":
    # the wrap at the end of the zone, and the live-TLD-without-DS case
    fixture("zzzzzzzz.", "WRAP (expect owner zw., next root)")
    fixture("aq.", "AQ (expect NS, no DS)")
    fixture("doosan.", "DOOSAN (terminated, expect a gap)")
