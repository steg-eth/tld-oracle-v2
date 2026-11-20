#!/usr/bin/env python3
"""Capture a 3 link DNSSEC chain ending in an algorithm 10 DNSKEY set.

    root DNSKEY  (alg 8, validated against the oracle's anchors)
    <tld> DS     (alg 8, signed by the root)
    <tld> DNSKEY (alg 10, self-signed, the link this project adds support for)

Reuses the primitives in ../../nsec/tools. Emits a Solidity fixture.
"""
import os, sys, struct, time
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "nsec", "tools"))
from mkchain import build_set, pick, signed            # noqa: E402
from mkfixture import parse, encode_name               # noqa: E402
from mknsec3 import ask, authoritative_ips, ROOT_A     # noqa: E402

T_DS, T_DNSKEY, T_RRSIG = 43, 48, 46


def chain3(tld):
    links, meta = [], []

    r = parse(ask(".", T_DNSKEY, ROOT_A))
    s = signed(r, T_DNSKEY, b"\x00")
    if not s:
        raise RuntimeError("no root DNSKEY")
    links.append(build_set(*s)); meta.append(("root DNSKEY", links[-1][2]))

    ow = encode_name(tld + ".")
    r = parse(ask(tld + ".", T_DS, ROOT_A))
    s = signed(r, T_DS, ow)
    if not s:
        raise RuntimeError(f"no root-signed DS for {tld}")
    links.append(build_set(*s)); meta.append((f"{tld} DS", links[-1][2]))
    ds_tags = {struct.unpack(">H", rec["rdata"][:2])[0] for rec in pick(r, T_DS, ow)}

    ips = authoritative_ips(tld)
    if not ips:
        raise RuntimeError(f"no authoritative address for {tld}")
    r = parse(ask(tld + ".", T_DNSKEY, ips[0]))
    keys = pick(r, T_DNSKEY, ow)
    sigs = pick(r, T_RRSIG, ow, covered=T_DNSKEY)
    if not keys or not sigs:
        raise RuntimeError(f"no DNSKEY for {tld}")
    # Match the KSK by key tag. Only the KSK is digested by the parent's DS; taking the first
    # RRSIG is the bug mkchain.py already recorded against `firmdale`.
    chosen = next((g for g in sigs
                   if struct.unpack(">H", g["rdata"][16:18])[0] in ds_tags), None)
    if chosen is None:
        raise RuntimeError(f"{tld}: no DNSKEY RRSIG matches DS tags {sorted(ds_tags)}")
    links.append(build_set(keys, chosen)); meta.append((f"{tld} DNSKEY", links[-1][2]))
    return links, meta


def main():
    tld = sys.argv[1] if len(sys.argv) > 1 else "swiss"
    links, meta = chain3(tld)
    algs = {m[1]["alg"] for m in meta}
    exp = min(m[1]["expiration"] for m in meta)
    inc = max(m[1]["inception"] for m in meta)
    print(f"// {tld}: algs {sorted(algs)}", file=sys.stderr)
    print(f"// window {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(inc))}"
          f" .. {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(exp))}", file=sys.stderr)
    for name, m in meta:
        print(f"//   {name}: alg {m['alg']} keytag {m['keytag']} signer {m['signer']}",
              file=sys.stderr)
    out = []
    out.append("// SPDX-License-Identifier: MIT")
    out.append("pragma solidity ^0.8.25;\n")
    out.append(f"/// Real DNSSEC chain for `{tld}.`, captured "
               f"{time.strftime('%d %B %Y', time.gmtime())}.")
    out.append(f"/// Valid {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(inc))}"
               f" to {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(exp))}.")
    out.append(f"library Alg10Fixture {{")
    out.append(f"    uint256 internal constant INSIDE = {(inc + exp)//2};")
    names = ["ROOT_DNSKEY", "TLD_DS", "TLD_DNSKEY"]
    for n, (s, sig, m) in zip(names, links):
        out.append(f'    bytes internal constant {n}_SET = hex"{s.hex()}";')
        out.append(f'    bytes internal constant {n}_SIG = hex"{sig.hex()}";')
    out.append("}")
    print("\n".join(out))


if __name__ == "__main__":
    main()
