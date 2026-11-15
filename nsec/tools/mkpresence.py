#!/usr/bin/env python3
"""Build an ENS DNSSEC presence-proof chain from live DNS, for gas measurement.

A TLD presence proof is four signed sets:
    root DNSKEY -> <tld> DS -> <tld> DNSKEY -> TXT
This script builds the same shape one level deeper, for a real signed name we
control, so every signature is genuine:
    root DNSKEY -> co DS -> co DNSKEY -> estmcmxci.co DS -> estmcmxci.co DNSKEY
                -> TXT _ens.estmcmxci.co
Six sets. Measuring prefixes of lengths 1..6 isolates the cost of each level,
so the four-set TLD figure is derived from measurement and not estimated.

Why not synthetic: nsec/test/SyntheticChainBuilder.sol signs with
DummyAlgorithm, which does no crypto, so it measures parsing and not
verification. Verification is the cost that matters here.

Reuses the SignedSet encoder in mkfixture.py. Canonical RR ordering inside a
set is by RDATA (RFC 4034 section 6.3); mkfixture's own build() sorts by owner
only, which is correct for a single-record NSEC set and wrong for a TXT set
with three records, so this file sorts before calling it.
"""
import json
import struct
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mkfixture as mk

RESOLVER = "1.1.1.1"
mk.TYPE.setdefault("TXT", 16)


def rquery(name, qtype, server=RESOLVER):
    """Like mkfixture.query but with RD set, for a recursive resolver.

    mkfixture talks straight to a root server, where RD must be off. A
    recursive resolver answers nothing useful without it.
    """
    import socket
    qid = 0x1234
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 1)   # RD on
    q = mk.encode_name(name) + struct.pack(">HH", mk.TYPE[qtype], 1)
    opt = b"\x00" + struct.pack(">HHIH", 41, 4096, 0x00008000, 0)
    pkt = header + q + opt
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(10)
    s.sendto(pkt, (server, 53))
    data, _ = s.recvfrom(65535)
    s.close()
    if len(data) >= 4 and (data[2] & 0x02):
        raise SystemExit(f"{name}/{qtype}: answer truncated, needs TCP")
    return data


def opaque(rr):
    """Canonical rdata for DNSKEY, DS and TXT: no embedded names."""
    return rr["rdata"]


def fetch_set(qname, qtype, covered_owner=None):
    """Return (blob, signature, meta, rr_count) for one signed RRset."""
    data = rquery(qname, qtype)
    rrs = mk.parse(data)
    want = mk.TYPE[qtype]
    owner = mk.encode_name(qname) if covered_owner is None else covered_owner
    members = [r for r in rrs if r["type"] == want and r["owner"] == owner]
    sigs = [r for r in rrs if r["type"] == mk.TYPE["RRSIG"]
            and r["owner"] == owner
            and struct.unpack(">H", r["rdata"][:2])[0] == want]
    if not members or not sigs:
        raise SystemExit(f"no {qtype} set or RRSIG for {qname} "
                         f"(members={len(members)} sigs={len(sigs)})")
    members.sort(key=lambda r: r["rdata"])          # RFC 4034 6.3
    blob, signature, meta = mk.build(members, sigs[0], opaque)
    return blob, signature, meta, len(members)


CHAIN = [
    (".",                      "DNSKEY", "root DNSKEY"),
    ("co.",                    "DS",     "co DS, signed by root"),
    ("co.",                    "DNSKEY", "co DNSKEY"),
    ("estmcmxci.co.",          "DS",     "estmcmxci.co DS, signed by co"),
    ("estmcmxci.co.",          "DNSKEY", "estmcmxci.co DNSKEY"),
    ("_ens.estmcmxci.co.",     "TXT",    "the claim TXT set"),
]


def main():
    out = []
    print("Presence chain, live from", RESOLVER)
    for qname, qtype, label in CHAIN:
        blob, sig, meta, n = fetch_set(qname, qtype)
        out.append({
            "step": len(out) + 1, "name": qname, "type": qtype,
            "label": label, "rrs": n,
            "alg": meta["alg"], "keytag": meta["keytag"],
            "inception": meta["inception"], "expiration": meta["expiration"],
            "rrset": "0x" + blob.hex(), "sig": "0x" + sig.hex(),
            "rrset_len": len(blob), "sig_len": len(sig),
        })
        print(f"  {len(out)}. {label:34} alg={meta['alg']:<3} "
              f"rrs={n}  rrset={len(blob):>4}B sig={len(sig):>4}B  "
              f"exp={meta['expiration']}")
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "presence-chain.json")
    with open(path, "w") as f:
        json.dump({"resolver": RESOLVER, "chain": out}, f, indent=2)
    exps = [c["expiration"] for c in out]
    print(f"\nwrote {path}")
    print(f"earliest RRSIG expiration in the chain: {min(exps)} "
          f"(unix); the whole chain dies at that moment")


if __name__ == "__main__":
    main()
