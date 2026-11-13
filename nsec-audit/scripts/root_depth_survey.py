"""Survey every NSEC record in the published root zone.

Tests the builder's liveness claim behind MAX_RECORD_LABELS = 1: that no NSEC record in
the root's chain has an owner name or a next-owner name more than one label below the root.
A single counterexample makes RootAbsencePredicate.RecordNameTooDeep a new false negative.

Input is the published root zone, which is the same data the root servers answer from:
  curl -o root.zone https://www.internic.net/domain/root.zone
Pass the path as an argument. The file is untrusted input and is only read, never executed.
"""
import sys, collections

def labels(name):
    """Label count of a presentation-format DNS name. The root has zero."""
    if name == ".":
        return 0
    n = name[:-1] if name.endswith(".") else name
    # presentation escapes: \. is a literal dot inside a label, \DDD is one byte
    out, i, count = [], 0, 1
    while i < len(n):
        if n[i] == "\\":
            i += 4 if (i + 1 < len(n) and n[i + 1].isdigit()) else 2
            continue
        if n[i] == ".":
            count += 1
        i += 1
    return count

path = sys.argv[1]
records = []
for line in open(path, encoding="utf-8", errors="replace"):
    if line.startswith(";") or not line.strip():
        continue
    f = line.split()
    # owner ttl class type rdata...
    if len(f) < 5 or f[2] != "IN" or f[3] != "NSEC":
        continue
    owner, nxt = f[0], f[4]
    records.append((owner, nxt, labels(owner), labels(nxt)))

print(f"NSEC records in the root zone: {len(records)}")
od = collections.Counter(r[2] for r in records)
nd = collections.Counter(r[3] for r in records)
print(f"owner      label-count histogram: {dict(sorted(od.items()))}")
print(f"next-owner label-count histogram: {dict(sorted(nd.items()))}")

deep = [r for r in records if r[2] > 1 or r[3] > 1]
print(f"\nrecords with an owner or next-owner deeper than one label: {len(deep)}")
for r in deep[:50]:
    print(f"  VIOLATION  {r[0]} NSEC {r[1]}   owner_labels={r[2]} next_labels={r[3]}")

# the two records the builder names, plus the chain's ends
byowner = {r[0]: r for r in records}
print("\nthe records the builder cites, and the chain's ends:")
for n in [".", "net.", "arpa.", "zw.", "aaa.", "domains.", "aq.", "com."]:
    r = byowner.get(n)
    print(f"  {n:10} -> {r[0] + ' NSEC ' + r[1] if r else 'NOT FOUND'}")

# does the chain close, and is it a single cycle over every record?
closing = [r for r in records if r[1] == "."]
print(f"\nrecords whose next-owner is the root (zone-closing): {len(closing)} -> {closing}")

# walk the chain from the apex and confirm it visits every record exactly once
seen, cur, steps = set(), ".", 0
while True:
    r = byowner.get(cur)
    if r is None:
        print(f"\nchain walk broke at {cur} after {steps} steps")
        break
    if cur in seen:
        print(f"\nchain walk revisited {cur} after {steps} steps")
        break
    seen.add(cur)
    steps += 1
    cur = r[1]
    if cur == ".":
        print(f"\nchain walk closed after {steps} steps, visiting {len(seen)} of {len(records)} records")
        break

# any name in the zone at all that is deeper than one label, NSEC or not
alldeep = collections.Counter()
owners_deep = set()
for line in open(path, encoding="utf-8", errors="replace"):
    if line.startswith(";") or not line.strip():
        continue
    f = line.split()
    if len(f) < 4 or f[2] != "IN":
        continue
    d = labels(f[0])
    alldeep[d] += 1
    if d > 1:
        owners_deep.add((f[0], f[3]))
print(f"\nall owner names in the zone, by label count: {dict(sorted(alldeep.items()))}")
types_deep = collections.Counter(t for _, t in owners_deep)
print(f"record types that appear at a name deeper than one label: {dict(types_deep)}")
print(f"distinct such names: {len(set(n for n, _ in owners_deep))}, for example "
      f"{sorted(set(n for n, _ in owners_deep))[:4]}")
