#!/usr/bin/env python3
# Deshace permutación de bits y genera out.enc por cada seed
import random, sys
from pathlib import Path

bits = list(Path('extracted_bmp.bits').read_text())
n = len(bits)
seeds = [s.strip() for s in Path('seeds_found.txt').read_text().splitlines() if s.strip()]

def lcg_shuffle(idxs, seed):
    a,c,m = 1103515245,12345,2**31
    state = int(seed,0) & (m-1)
    arr = list(idxs)
    for i in range(len(arr)-1,0,-1):
        state = (a*state+c)%m
        j = state % (i+1)
        arr[i],arr[j] = arr[j],arr[i]
    return arr

def shuffle_with(seed, rng_type, n):
    try:
        seed_int = int(seed)  # forzamos decimal
    except ValueError:
        seed_int = hash(seed)  # si no es decimal, usamos hash
    if rng_type == 'python_mt':
        r = random.Random(seed_int)
        lst = list(range(n))
        r.shuffle(lst)
        return lst
    if rng_type == 'lcg':
        a,c,m = 1103515245,12345,2**31
        state = seed_int & (m-1)
        arr = list(range(n))
        for i in range(len(arr)-1,0,-1):
            state = (a*state+c)%m
            j = state % (i+1)
            arr[i],arr[j] = arr[j],arr[i]
        return arr
    raise SystemExit("rng_type debe ser python_mt o lcg")


def bits_to_bytes(bits, msb=True):
    out = bytearray()
    for i in range(0,len(bits),8):
        chunk = bits[i:i+8]
        if len(chunk)<8: break
        if msb:
            v=0
            for b in chunk: v=(v<<1)|int(b)
        else:
            v=0
            for idx,b in enumerate(chunk):
                if b=='1': v|=(1<<idx)
        out.append(v)
    return bytes(out)

for seed in seeds:
    for rng_type in ['python_mt','lcg']:
        perm = shuffle_with(seed, rng_type, n)
        inv = [0]*n
        for i,v in enumerate(perm): inv[v]=i
        reordered = [bits[inv[i]] for i in range(n)]
        data = bits_to_bytes(reordered, msb=True)
        fname = f'out_enc_{seed}_{rng_type}.enc'
        Path(fname).write_bytes(data)
        print(f"Wrote {fname} ({len(data)} bytes)")
