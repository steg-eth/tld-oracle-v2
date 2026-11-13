import datetime
def ts(x): return datetime.datetime.fromtimestamp(x, datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%SZ')
TYPES={2:'NS',6:'SOA',43:'DS',46:'RRSIG',47:'NSEC',48:'DNSKEY',63:'ZONEMD',16:'TXT'}
def rdname(b,i):
    out=[];start=i
    while True:
        l=b[i]
        if l==0: i+=1; break
        out.append(b[i+1:i+1+l].decode('ascii','replace')); i+=1+l
    return ('.'.join(out)+'.' if out else '.'), i
def bitmap(b,i):
    found=[]
    while i<len(b):
        w=b[i]; ln=b[i+1]; blk=b[i+2:i+2+ln]
        for bi,byte in enumerate(blk):
            for bit in range(8):
                if byte>>(7-bit)&1: found.append(w*256+bi*8+bit)
        i+=2+ln
    return found
def decode(name,h):
    b=bytes.fromhex(h)
    tc=int.from_bytes(b[0:2],'big'); alg=b[2]; labels=b[3]
    ttl=int.from_bytes(b[4:8],'big'); exp=int.from_bytes(b[8:12],'big'); inc=int.from_bytes(b[12:16],'big')
    kt=int.from_bytes(b[16:18],'big')
    signer,i=rdname(b,18)
    print(f"### {name}")
    print(f"  RRSIG: typeCovered={tc}({TYPES.get(tc,'?')}) alg={alg} labels={labels} ttl={ttl} keytag={kt}")
    print(f"         inception={inc} ({ts(inc)})  expiration={exp} ({ts(exp)})  signer='{signer}'")
    # records
    while i<len(b):
        owner,j=rdname(b,i)
        t=int.from_bytes(b[j:j+2],'big'); cl=int.from_bytes(b[j+2:j+4],'big')
        rttl=int.from_bytes(b[j+4:j+8],'big'); rdl=int.from_bytes(b[j+8:j+10],'big')
        rd=b[j+10:j+10+rdl]
        print(f"  RR: owner='{owner}' type={t}({TYPES.get(t,'?')}) class={cl} ttl={rttl} rdlength={rdl}")
        if t==47:
            nxt,k=rdname(rd,0)
            bits=bitmap(rd,k)
            print(f"      next='{nxt}'  bitmapOffset={k}  types={[TYPES.get(x,str(x)) for x in bits]}  rawBitmap={rd[k:].hex()}")
        elif t==48:
            fl=int.from_bytes(rd[0:2],'big')
            print(f"      DNSKEY flags=0x{fl:04x} proto={rd[2]} alg={rd[3]} keylen={len(rd)-4}")
        i=j+10+rdl
    print()
F={
 "ANCHORS (constructor arg, DS RRs)":"00002b000100000e1000244f660802e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d00002b000100000e10002497280802683d2d0acb8c9b712a1948b27f741219298d0a450d612c483af444a4c0fb2b16",
 "ZW_SET (zw. NSEC .)":"002f0801000151806b0519d06af3e840223b00027a7700002f0001000151800009000006200000000003",
 "AQ_SET (aq. NSEC aquarelle.)":"002f0801000151806b0519d06af3e840223b0002617100002f0001000151800013096171756172656c6c65000006200000000003",
 "DOMAINS_SET (domains. NSEC dot.)":"002f0801000151806b0519d06af3e840223b0007646f6d61696e7300002f000100015180000d03646f74000006200000000013",
 "ROOT_SET (. NSEC aaa.)":"002f0800000151806b0519d06af3e840223b0000002f000100015180000f036161610000082200000000038001",
 "CORRUPT (domains. NSEC dou.)":"002f0801000151806b0519d06af3e840223b0007646f6d61696e7300002f000100015180000d03646f75000006200000000013",
}
# anchors are bare DS RRs, not a signed set: decode separately
anc=bytes.fromhex(F.pop("ANCHORS (constructor arg, DS RRs)"))
print("### ANCHORS (bare DS RRs, oracle constructor arg)")
i=0
while i<len(anc):
    owner,j=rdname(anc,i)
    t=int.from_bytes(anc[j:j+2],'big'); rdl=int.from_bytes(anc[j+8:j+10],'big'); rd=anc[j+10:j+10+rdl]
    print(f"  RR owner='{owner}' type={t}({TYPES.get(t,'?')}) rdlength={rdl} keytag={int.from_bytes(rd[0:2],'big')} alg={rd[2]} digesttype={rd[3]} digest={rd[4:].hex()}")
    i=j+10+rdl
print()
for k,v in F.items(): decode(k,v)
print("### key timestamps")
for n,v in [("INSIDE",1794415402),("AFTER_NSEC_EXPIRY",1795496401),("BEFORE_NSEC_INCEPTION",1794369599),("DNSKEY exp 0x6b0e0e00",0x6b0e0e00),("DNSKEY inc 0x6af25e80",0x6af25e80)]:
    print(f"  {n} = {v} ({ts(v)})")
