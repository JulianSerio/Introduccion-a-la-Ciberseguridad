#!/usr/bin/env python3
# XOR con SHA256(seed+counter) y produce out.dec
import hashlib
from pathlib import Path

def keystream(seed_bytes,nbytes,ctr_len=4,ctr_end='big',order='seed_ctr'):
    out = bytearray()
    blk = 0
    maxv = 1<<(ctr_len*8)
    while len(out)<nbytes:
        ctr=(blk%maxv).to_bytes(ctr_len,ctr_end)
        h=hashlib.sha256(seed_bytes+ctr).digest() if order=='seed_ctr' else hashlib.sha256(ctr+seed_bytes).digest()
        out.extend(h); blk+=1
    return bytes(out[:nbytes])

seeds = [s.strip() for s in Path('seeds_found.txt').read_text().splitlines() if s.strip()]
enc_files = list(Path('.').glob('out_enc_*.enc'))

for encf in enc_files:
    enc = encf.read_bytes()
    seed = encf.stem.split('_')[2]
    for mode in ['int_be','int_le','hex','str']:
        try:
            if mode=='int_be':
                sb=int(seed,0).to_bytes(4,'big')
            elif mode=='int_le':
                sb=int(seed,0).to_bytes(4,'little')
            elif mode=='hex':
                sb=bytes.fromhex(seed[2:] if seed.startswith('0x') else seed)
            else:
                sb=seed.encode()
            ks = keystream(sb,len(enc))
            plain = bytes(a^b for a,b in zip(enc,ks))
            outname = f"{encf.stem}_dec_{mode}.dec"
            Path(outname).write_bytes(plain)
            print(f"Wrote {outname}")
        except Exception as e:
            continue
