#!/usr/bin/env python3
"""Expected NSEC3 hashes, for the NSEC3Utils test suite.

The captured NSEC3 fixtures carry owner hashes but not their preimages, so they
cannot verify a hash implementation on their own. This generates ground truth.

NSEC3 hashing, RFC 5155 section 5:
    IH(salt, x, 0) = H(x || salt)
    IH(salt, x, k) = H(IH(salt, x, k-1) || salt)
    hash(name)     = IH(salt, wire(name), iterations)
`name` is the lowercase, uncompressed wire form. H is SHA-1 for algorithm 1,
which is the only algorithm defined for NSEC3.

Self-checked against RFC 5155 Appendix A, whose example zone uses salt aabbccdd
and 12 iterations.
"""
import hashlib

B32HEX = "0123456789abcdefghijklmnopqrstuv"


def wire(name):
    out = b""
    for label in name.rstrip(".").split("."):
        if label:
            out += bytes([len(label)]) + label.encode("ascii").lower()
    return out + b"\x00"


def nsec3_hash(name, salt=b"", iterations=0):
    h = hashlib.sha1(wire(name) + salt).digest()
    for _ in range(iterations):
        h = hashlib.sha1(h + salt).digest()
    return h


def b32hex(b):
    bits = "".join(f"{x:08b}" for x in b)
    bits += "0" * (-len(bits) % 5)
    return "".join(B32HEX[int(bits[i:i + 5], 2)] for i in range(0, len(bits), 5))


RFC_A = [  # RFC 5155 Appendix A, salt aabbccdd, 12 iterations
    ("example.",     "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom"),
    ("a.example.",   "35mthgpgcu1qg68fab165klnsnk3dpvl"),
    ("ai.example.",  "gjeqe526plbf1g8mklp59enfd789njgi"),
    ("ns1.example.", "2t7b4g4vsa5smi47k61mv5bv1a22bojr"),
    ("ns2.example.", "q04jkcevqvmu85r014c7dkba38o0ji5r"),
    ("w.example.",   "k8udemvp1j2f7eg6jebps17vp3n8i58h"),
    ("*.w.example.", "r53bq7cc2uvmubfu5ocmm6pers9tk9en"),
    ("x.w.example.", "b4um86eghhds6nea196smvmlo4ors995"),
]

if __name__ == "__main__":
    print("=== self-check against RFC 5155 Appendix A (salt aabbccdd, 12 iterations)")
    bad = 0
    for name, want in RFC_A:
        got = b32hex(nsec3_hash(name, bytes.fromhex("aabbccdd"), 12))
        ok = got == want
        bad += not ok
        print(f"  {'ok  ' if ok else 'FAIL'} {name:14} {got}")
    print(f"  {len(RFC_A) - bad}/{len(RFC_A)} match")
    if bad:
        raise SystemExit("generator is wrong, do not use its output")

    print("\n=== vectors for the captured zones")
    zones = [("desi", b"", 0), ("firmdale", bytes.fromhex("abbacafe"), 20),
             ("nowruz", b"", 0)]
    for tld, salt, iters in zones:
        for nm in (f"_ens.{tld}.", f"{tld}."):
            h = nsec3_hash(nm, salt, iters)
            print(f"  {nm:18} salt={salt.hex() or '-':9} iter={iters:<3} "
                  f"sha1={h.hex()}  b32={b32hex(h)}")
