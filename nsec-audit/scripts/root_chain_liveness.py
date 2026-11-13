"""Simulate RootAbsencePredicate's round 3 comparator over the entire real root NSEC chain.

Two properties, checked against every record the root actually publishes:

  LIVENESS   every absent name is covered by at least one record in the chain, and the new
             rule finds it. A failure here is a releasable TLD that can never prove absence.
  SOUNDNESS  no live top-level domain is covered by any record in the chain. A failure here
             is a live delegation reported absent.

The rule, as shipped in NSECUtils.coversName:
    owner < name, and either (next == apex and owner != apex), or name < next.

Also re-derives the shape statistics the builder reports, independently.

Input is the published root zone, which is the data the root servers answer from:
  curl -o root.zone https://www.internic.net/domain/root.zone
Pass the path as an argument. The file is untrusted input and is only read, never executed.
"""
import sys, collections

def wire_labels(name):
    """Presentation name -> list of label byte strings. The root is []."""
    if name == ".":
        return []
    n = name[:-1] if name.endswith(".") else name
    out, cur, i = [], bytearray(), 0
    while i < len(n):
        c = n[i]
        if c == "\\":
            if i + 1 < len(n) and n[i + 1 : i + 4].isdigit():
                cur.append(int(n[i + 1 : i + 4])); i += 4; continue
            cur.append(ord(n[i + 1])); i += 2; continue
        if c == ".":
            out.append(bytes(cur)); cur = bytearray(); i += 1; continue
        cur.append(ord(c)); i += 1
    out.append(bytes(cur))
    return out

def cmp_names(a, b):
    """RRUtils.compareNames, for names given as label lists. Canonical DNS order."""
    if a == b:
        return 0
    x, y = list(a), list(b)
    # compare from the rightmost label
    while x and y:
        la, lb = x[-1], y[-1]
        if la != lb:
            m = min(len(la), len(lb))
            if la[:m] != lb[:m]:
                return -1 if la[:m] < lb[:m] else 1
            return -1 if len(la) < len(lb) else 1
        x.pop(); y.pop()
    if not x and y:
        return -1   # a is a suffix of b, so it sorts first
    if x and not y:
        return 1
    return 0

APEX = []  # the root, zero labels

def covers(owner, next_, name, apex=APEX):
    """NSECUtils.coversName, round 3."""
    if cmp_names(owner, name) >= 0:
        return False
    if next_ == apex:
        return owner != apex
    return cmp_names(name, next_) < 0

def covers_old(owner, next_, name):
    """The round 2 rule, for comparison: closing branch on next <= owner."""
    if cmp_names(owner, name) >= 0:
        return False
    if cmp_names(next_, owner) <= 0:
        return True
    return cmp_names(name, next_) < 0

path = sys.argv[1]
serial = None
recs = []
for line in open(path, encoding="utf-8", errors="replace"):
    if line.startswith(";") or not line.strip():
        continue
    f = line.split()
    if serial is None and len(f) > 6 and f[3] == "SOA":
        serial = f[6]
    if len(f) < 5 or f[2] != "IN" or f[3] != "NSEC":
        continue
    recs.append((wire_labels(f[0]), wire_labels(f[4]), f[0], f[4]))

print(f"root zone serial: {serial}")
print(f"NSEC records: {len(recs)}")

od = collections.Counter(len(r[0]) for r in recs)
nd = collections.Counter(len(r[1]) for r in recs)
print(f"owner label counts: {dict(sorted(od.items()))}")
print(f"next  label counts: {dict(sorted(nd.items()))}")
print(f"records deeper than one label: "
      f"{sum(1 for r in recs if len(r[0]) > 1 or len(r[1]) > 1)}")
print(f"records with next == owner: {sum(1 for r in recs if r[0] == r[1])}")

new_closing = [r for r in recs if r[1] == APEX]
old_closing = [r for r in recs if cmp_names(r[1], r[0]) <= 0]
print(f"records taking the NEW closing branch (next == apex): {len(new_closing)}"
      f" -> {[(r[2], r[3]) for r in new_closing]}")
print(f"records taking the OLD closing branch (next <= owner): {len(old_closing)}"
      f" -> {[(r[2], r[3]) for r in old_closing]}")
print(f"apex-owned records: {[(r[2], r[3]) for r in recs if r[0] == APEX]}")

# ---------------------------------------------------------------- LIVENESS over the whole chain
# For each record, a probe name strictly inside its gap.
probes = []
for owner, next_, so, sn in recs:
    if owner == APEX:
        probe = [b"\x00"]          # one label, sorts below any real TLD label
    else:
        probe = [owner[0] + b"\x00"]  # immediately above owner, below any next above it
    probes.append((probe, so, sn))

fail_live = 0
for idx, (probe, so, sn) in enumerate(probes):
    owner, next_ = recs[idx][0], recs[idx][1]
    if not covers(owner, next_, probe):
        fail_live += 1
        print(f"  LIVENESS FAIL: {so} NSEC {sn} does not cover its own gap probe")
    if covers(owner, next_, probe) != covers_old(owner, next_, probe):
        print(f"  RULES DISAGREE on the real chain: {so} NSEC {sn}")
print(f"\nLIVENESS: {len(probes) - fail_live}/{len(probes)} records cover a name inside "
      f"their own gap, under the round 3 rule")

# every probe is covered by exactly one record in the chain
multi = under = 0
for probe, so, sn in probes:
    hits = sum(1 for o, n, _, _ in recs if covers(o, n, probe))
    if hits == 0:
        under += 1; print(f"  PARTITION FAIL: probe in {so} gap covered by no record")
    elif hits > 1:
        multi += 1; print(f"  PARTITION FAIL: probe in {so} gap covered by {hits} records")
print(f"PARTITION: every one of {len(probes)} gap probes is covered by exactly one record: "
      f"{under == 0 and multi == 0}")

# ---------------------------------------------------------------- SOUNDNESS over the whole chain
live = [r[0] for r in recs if r[0] != APEX]
print(f"\nSOUNDNESS: checking {len(live)} live top-level names against all {len(recs)} records "
      f"({len(live) * len(recs)} evaluations)")
bad = 0
for name in live:
    for o, n, so, sn in recs:
        if covers(o, n, name):
            bad += 1
            print(f"  SOUNDNESS FAIL: {so} NSEC {sn} covers the live name "
                  f"{'.'.join(l.decode('ascii','replace') for l in name)}.")
            break
print(f"SOUNDNESS: live top-level names reported absent by any record: {bad}")

# the two G1 shapes, for the record
print("\nthe two shapes round 2 found, evaluated under the round 3 rule:")
com, net = [b"com"], [b"net"]
print(f"  com. NSEC com. covers net.: {covers(com, com, net)}")
print(f"  .    NSEC .    covers com.: {covers(APEX, APEX, com)}")
print(f"  com. NSEC .    covers net.: {covers(com, APEX, net)}   <- a well formed closing")
print(f"                                   shape with a false owner, see T47")
