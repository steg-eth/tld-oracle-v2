#!/usr/bin/env python3
"""Capture a full DNSSEC chain for an NSEC3 denial inside a TLD zone.

mkfixture.py captures root-signed sets, which is a 2 link chain because the root
signs its own NSEC records. A TLD zone needs 4 links:

    root DNSKEY  (validated against the oracle's anchors)
    <tld> DS     (signed by the root)
    <tld> DNSKEY (validated against that DS)
    <tld> NSEC3  (signed by the TLD)

Emits a Solidity fixture file in the shape of test/RootFixtures.sol.
"""
import socket
import struct
import sys
import time
from mkfixture import read_name, parse, encode_name, wire_to_str, decode_bitmap
from mknsec3 import ask, authoritative_ips, ROOT_A, b32hex_label
from mknsec3 import T_RRSIG, T_NSEC3

T_DS, T_DNSKEY, T_TXT = 43, 48, 16


def build_set(rrs, rrsig):
    """ENS SignedSet blob and signature. RRs in RFC 4035 canonical order.

    mkfixture.build sorts by owner only, which is enough for a one record set.
    A DNSKEY set holds several records under one owner, so this also sorts by
    rdata, per RFC 4034 section 6.3.
    """
    sig = rrsig["rdata"]
    typecovered, alg, labels, origttl, expiration, inception, keytag = \
        struct.unpack(">HBBIIIH", sig[:18])
    signer, soff = read_name(rrsig["raw"], rrsig["rdata_off"] + 18)
    signature = sig[18 + (soff - (rrsig["rdata_off"] + 18)):]
    head = struct.pack(">HBBIIIH", typecovered, alg, labels, origttl,
                       expiration, inception, keytag) + signer
    body = b""
    for rr in sorted(rrs, key=lambda r: (r["owner"], r["rdata"])):
        rd = rr["rdata"]
        body += rr["owner"] + struct.pack(">HHIH", rr["type"], rr["class"],
                                          origttl, len(rd)) + rd
    return head + body, signature, {"inception": inception,
                                    "expiration": expiration,
                                    "keytag": keytag, "alg": alg,
                                    "signer": wire_to_str(signer)}


def pick(rrs, rtype, owner=None, covered=None):
    out = [r for r in rrs if r["type"] == rtype
           and (owner is None or r["owner"] == owner)]
    if covered is not None:
        out = [r for r in out
               if struct.unpack(">H", r["rdata"][:2])[0] == covered]
    return out


def signed(rrs, rtype, owner):
    """One (set, rrsig) pair for a type under an owner."""
    body = pick(rrs, rtype, owner)
    sigs = pick(rrs, T_RRSIG, owner, covered=rtype)
    if not body or not sigs:
        return None
    return body, sigs[0]


def chain(tld, qname=None):
    qname = qname or f"_ens.{tld}"
    links, meta = [], []

    # 1. root DNSKEY
    r = parse(ask(".", T_DNSKEY, ROOT_A))
    s = signed(r, T_DNSKEY, b"\x00")
    if not s:
        raise RuntimeError("no root DNSKEY")
    links.append(build_set(*s)); meta.append(("root DNSKEY", links[-1][2]))

    # 2. <tld> DS, signed by the root
    r = parse(ask(tld + ".", T_DS, ROOT_A))
    ow = encode_name(tld + ".")
    s = signed(r, T_DS, ow)
    if not s:
        raise RuntimeError(f"no root-signed DS for {tld}")
    links.append(build_set(*s)); meta.append((f"{tld} DS", links[-1][2]))

    ips = authoritative_ips(tld)
    if not ips:
        raise RuntimeError(f"no authoritative address for {tld}")
    ip = ips[0]

    # 3. <tld> DNSKEY, signed by a key the DS actually digests.
    #
    #    A zone usually publishes two RRSIGs over its DNSKEY set, one by the KSK and one by
    #    the ZSK. Only the KSK is digested by the DS in the parent, so only the KSK's
    #    signature lets the oracle tie the set to the DS. Taking the first RRSIG works by
    #    luck: `desi` and `nowruz` list the KSK first and `firmdale` does not, which failed
    #    with NoMatchingProof until this matched on the key tag instead.
    ds_tags = {struct.unpack(">H", rec["rdata"][:2])[0]
               for rec in pick(parse(ask(tld + ".", T_DS, ROOT_A)), T_DS, ow)}
    r = parse(ask(tld + ".", T_DNSKEY, ip))
    keys = pick(r, T_DNSKEY, ow)
    sigs = pick(r, T_RRSIG, ow, covered=T_DNSKEY)
    if not keys or not sigs:
        raise RuntimeError(f"no DNSKEY for {tld}")
    chosen = next((g for g in sigs
                   if struct.unpack(">H", g["rdata"][16:18])[0] in ds_tags), None)
    if chosen is None:
        raise RuntimeError(
            f"{tld}: no DNSKEY RRSIG matches a DS key tag {sorted(ds_tags)}; "
            f"RRSIG tags are "
            f"{sorted(struct.unpack('>H', g['rdata'][16:18])[0] for g in sigs)}")
    links.append(build_set(keys, chosen)); meta.append((f"{tld} DNSKEY", links[-1][2]))

    # 4. the NSEC3 records that deny qname
    d = parse(ask(qname + ".", T_TXT, ip))
    n3 = pick(d, T_NSEC3)
    if not n3:
        raise RuntimeError(f"no NSEC3 denying {qname}")
    n3links = []
    for rec in n3:
        sigs = pick(d, T_RRSIG, rec["owner"], covered=T_NSEC3)
        if not sigs:
            continue
        blob, sg, m = build_set([rec], sigs[0])
        a, f, it, sl = struct.unpack(">BBHB", rec["rdata"][:5])
        salt = rec["rdata"][5:5 + sl]
        o = 5 + sl
        hl = rec["rdata"][o]
        n3links.append({
            "blob": blob, "sig": sg, "meta": m,
            "owner": rec["owner"], "ownerhash": b32hex_label(rec["owner"]),
            "nexthash": rec["rdata"][o + 1:o + 1 + hl],
            "flags": f, "iterations": it, "salt": salt,
            "bitmap": rec["rdata"][o + 1 + hl:],
        })
    if not n3links:
        raise RuntimeError(f"no signed NSEC3 denying {qname}")
    return links, meta, n3links, qname, ip


def window(metas):
    inc = max(m["inception"] for m in metas)
    exp = min(m["expiration"] for m in metas)
    return inc, exp


def _main():
    args = [a for a in sys.argv[1:] if a != "--sol"]
    tlds = args or ["desi", "firmdale", "nowruz"]
    if "--sol" in sys.argv:
        emit_sol(tlds, "../test/NSEC3Fixtures.sol")
        return
    for tld in tlds:
        try:
            links, meta, n3, qname, ip = chain(tld)
        except Exception as e:
            print(f"[{tld}] {type(e).__name__}: {e}")
            continue
        metas = [m for _, m in meta] + [x["meta"] for x in n3]
        inc, exp = window(metas)
        print(f"\n=== {tld}  query={qname}  via {ip}")
        print(f"    chain links above the NSEC3 set: {len(links)}")
        for label, m in meta:
            print(f"      {label:22} alg={m['alg']} keytag={m['keytag']} signer={m['signer']}")
        for x in n3:
            print(f"      NSEC3 {x['ownerhash'].hex()[:16]}.. flags={x['flags']} "
                  f"iter={x['iterations']} salt={x['salt'].hex() or '-'} "
                  f"types={decode_bitmap(x['bitmap'])}")
        print(f"    valid window: {inc} .. {exp}  "
              f"({time.strftime('%Y-%m-%d %H:%M:%SZ', time.gmtime(inc))} .. "
              f"{time.strftime('%Y-%m-%d %H:%M:%SZ', time.gmtime(exp))})")
        if exp <= inc:
            print("    WARNING: the links have no common validity window")


# --------------------------------------------------------------------- solidity emitter

def ds_digest_types(tld):
    r = parse(ask(tld + ".", T_DS, ROOT_A))
    out = set()
    for rec in pick(r, T_DS, encode_name(tld + ".")):
        out.add(rec["rdata"][3])
    return sorted(out)


def emit_sol(tlds, path):
    zones, inc, exp, digests = [], 0, 1 << 62, set()
    root_link = None
    for tld in tlds:
        links, meta, n3, qname, ip = chain(tld)
        if root_link is None:
            root_link = links[0]
        metas = [m for _, m in meta] + [x["meta"] for x in n3]
        inc = max([inc] + [m["inception"] for m in metas])
        exp = min([exp] + [m["expiration"] for m in metas])
        digests |= set(ds_digest_types(tld))
        zones.append({"tld": tld, "qname": qname, "ip": ip,
                      "ds": links[1], "dnskey": links[2], "n3": n3})
    at = (inc + exp) // 2
    L = []
    w = L.append
    w("// SPDX-License-Identifier: MIT")
    w("pragma solidity ^0.8.25;")
    w("")
    w('import {DNSSEC} from "../src/contracts/dnssec-oracle/DNSSEC.sol";')
    w('import {DNSSECImpl} from "../src/contracts/dnssec-oracle/DNSSECImpl.sol";')
    w('import {RSASHA256Algorithm} from "../src/contracts/dnssec-oracle/algorithms/RSASHA256Algorithm.sol";')
    w('import {SHA256Digest} from "../src/contracts/dnssec-oracle/digests/SHA256Digest.sol";')
    w('import {SHA1Digest} from "../src/contracts/dnssec-oracle/digests/SHA1Digest.sol";')
    w('import {Cheats} from "./Cheats.sol";')
    w("")
    w("/// Not a test file. Real NSEC3 denial-of-existence fixtures from inside TLD zones.")
    w("///")
    w("/// The sibling of RootFixtures.sol. That file holds root-signed NSEC, which is a 2 link")
    w("/// chain because the root signs the root. These are 4 link chains:")
    w("///")
    w("///     root DNSKEY -> <tld> DS -> <tld> DNSKEY -> <tld> NSEC3")
    w("///")
    w("/// Captured with `python3 tools/mkchain.py --sol` on %s."
      % time.strftime('%d %B %Y', time.gmtime()))
    w("/// Each zone is the denial of `_ens.<tld>`, which no TLD publishes.")
    w("///")
    w("/// **These fixtures expire. Every link is valid %s to %s,"
      % (time.strftime('%Y-%m-%d %H:%M:%SZ', time.gmtime(inc)),
         time.strftime('%Y-%m-%d %H:%M:%SZ', time.gmtime(exp))))
    w("/// and `AT` sits inside that window. After that date every test built on them fails on")
    w("/// signature expiry, which looks exactly like a defect in the predicate and is not one.**")
    w("/// The window is bounded by the root's own DS and DNSKEY signatures, so a refresh buys")
    w("/// about two weeks. To refresh: `python3 tools/mkchain.py --sol`.")
    w("///")
    w("/// Why these three zones, from survey/NSEC3-CENSUS-2026-11-19.md:")
    w("///")
    for z in zones:
        f = z["n3"][0]
        w("///   - `%s`: %d NSEC3 record(s), opt-out %s, %d iterations, salt %s"
          % (z["tld"], len(z["n3"]),
             "set" if any(x["flags"] & 1 for x in z["n3"]) else "clear",
             f["iterations"], f["salt"].hex() or "none"))
    w("///")
    w("/// **The record count is not fixed.** RFC 5155 sections 8.4 and 8.5 allow up to three")
    w("/// records in a denial, and these three zones return three, one and two. A reader that")
    w("/// assumes a count is wrong.")
    w("///")
    w("/// All three zones sign with algorithm 8, which the oracle supports. 32 TLDs sign with")
    w("/// algorithms 10, 14 or 15 and cannot be verified at all. See the census.")
    w("abstract contract NSEC3Fixtures is Cheats {")
    w("    /// @dev Inside every window above.")
    w("    uint256 internal constant AT = %d; // %s"
      % (at, time.strftime('%Y-%m-%d %H:%M:%SZ', time.gmtime(at))))
    w("    uint256 internal constant BEFORE_INCEPTION = %d;" % (inc - 1))
    w("    uint256 internal constant AFTER_EXPIRY = %d;" % (exp + 1))
    w("")
    w("    bytes internal constant ANCHORS =")
    w('        hex"00002b000100000e1000244f660802e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d00002b000100000e10002497280802683d2d0acb8c9b712a1948b27f741219298d0a450d612c483af444a4c0fb2b16";')
    w("    bytes internal constant ROOT_DNSKEY_SET =")
    w('        hex"%s";' % root_link[0].hex())
    w("    bytes internal constant ROOT_DNSKEY_SIG =")
    w('        hex"%s";' % root_link[1].hex())
    for z in zones:
        u = z["tld"].upper().replace("-", "_")
        w("")
        w("    // ---- %s, %s" % (z["tld"], z["qname"]))
        w("    bytes internal constant %s_NAME = hex\"%s\"; // %s."
          % (u, encode_name(z["tld"] + ".").hex(), z["tld"]))
        w("    bytes internal constant %s_QNAME = hex\"%s\"; // %s."
          % (u, encode_name(z["qname"] + ".").hex(), z["qname"]))
        w("    bytes internal constant %s_DS_SET = hex\"%s\";" % (u, z["ds"][0].hex()))
        w("    bytes internal constant %s_DS_SIG = hex\"%s\";" % (u, z["ds"][1].hex()))
        w("    bytes internal constant %s_DNSKEY_SET = hex\"%s\";" % (u, z["dnskey"][0].hex()))
        w("    bytes internal constant %s_DNSKEY_SIG = hex\"%s\";" % (u, z["dnskey"][1].hex()))
        for i, x in enumerate(z["n3"]):
            w("    /// @dev ownerhash %s nexthash %s flags %d iterations %d salt %s"
              % (x["ownerhash"].hex(), x["nexthash"].hex(), x["flags"],
                 x["iterations"], x["salt"].hex() or "none"))
            w("    bytes internal constant %s_NSEC3_%d_SET = hex\"%s\";" % (u, i, x["blob"].hex()))
            w("    bytes internal constant %s_NSEC3_%d_SIG = hex\"%s\";" % (u, i, x["sig"].hex()))
        w("    uint256 internal constant %s_NSEC3_COUNT = %d;" % (u, len(z["n3"])))
    w("")
    w("    /// @dev Digest 1 is registered because at least one of these zones publishes a")
    w("    ///      SHA-1 DS in the root. The mainnet oracle registers both digests, so this")
    w("    ///      matches it. RootFixtures registers only digest 2, which is enough for the")
    w("    ///      root's own chain and not enough here.")
    w("    function _realOracle() internal returns (DNSSECImpl oracle) {")
    w("        oracle = new DNSSECImpl(ANCHORS);")
    w("        oracle.setAlgorithm(8, new RSASHA256Algorithm());")
    w("        oracle.setDigest(1, new SHA1Digest());")
    w("        oracle.setDigest(2, new SHA256Digest());")
    w("    }")
    w("")
    w("    /// @notice root DNSKEY, then the zone's DS, DNSKEY and one NSEC3 set.")
    w("    function _chain4(")
    w("        bytes memory dsSet, bytes memory dsSig,")
    w("        bytes memory keySet, bytes memory keySig,")
    w("        bytes memory n3Set, bytes memory n3Sig")
    w("    ) internal pure returns (DNSSEC.RRSetWithSignature[] memory chain) {")
    w("        chain = new DNSSEC.RRSetWithSignature[](4);")
    w("        chain[0] = DNSSEC.RRSetWithSignature(ROOT_DNSKEY_SET, ROOT_DNSKEY_SIG);")
    w("        chain[1] = DNSSEC.RRSetWithSignature(dsSet, dsSig);")
    w("        chain[2] = DNSSEC.RRSetWithSignature(keySet, keySig);")
    w("        chain[3] = DNSSEC.RRSetWithSignature(n3Set, n3Sig);")
    w("    }")
    w("}")
    open(path, "w").write("\n".join(L) + "\n")
    print(f"wrote {path}")
    print(f"  zones: {', '.join(z['tld'] for z in zones)}")
    print(f"  DS digest types seen: {sorted(digests)} (2 = SHA-256)")
    print(f"  window {inc} .. {exp}, AT = {at}")


if __name__ == "__main__":
    _main()
