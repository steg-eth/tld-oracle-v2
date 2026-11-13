import hashlib, os, sys
tree = "/tmp/upstream-a18fdc0/upstream-tree.txt"
root = "/Users/oakgroup/gtld-ens-integration/tld-oracle-v2/nsec-audit/tree/src"
def blob(p):
    d = open(p,'rb').read()
    return hashlib.sha1(b"blob %d\0" % len(d) + d).hexdigest(), hashlib.sha256(d).hexdigest()
ok=bad=missing=0
rows=[]
for line in open(tree):
    sha, path = line.split()
    lp = os.path.join(root, path)
    if not os.path.exists(lp):
        continue
    b, s256 = blob(lp)
    match = (b == sha)
    rows.append((path, "OK" if match else "MISMATCH", b, sha, s256))
    if match: ok+=1
    else: bad+=1
for r in rows:
    print(f"{r[1]:9} {r[0]}")
    if r[1]!="OK": print(f"          local={r[2]} upstream={r[3]}")
print(f"\nchecked={ok+bad} ok={ok} mismatch={bad}")
print("\n--- local files under contracts/ NOT in upstream pin list ---")
up = {l.split()[1] for l in open(tree)}
for dp,_,fs in os.walk(os.path.join(root,"contracts")):
    for f in fs:
        rel = os.path.relpath(os.path.join(dp,f), root)
        if rel not in up: print("  EXTRA:", rel)
print("\n--- sha256, for cross-check against UPSTREAM-SOURCES.lock ---")
for r in rows:
    if r[0].startswith("contracts/dnssec-oracle/"): print(r[4], r[0])
