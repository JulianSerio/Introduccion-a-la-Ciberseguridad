#!/usr/bin/env python3
"""
unscatter_and_decrypt.py
Sin parámetros. Usa:
 - seeds_found.txt  (usa la primera línea si hay varias)
 - extracted_bmp.bmp (o extracted_bmp.bits si ya existe)
Genera resultados en outputs_quick/
"""
from pathlib import Path
from PIL import Image
import hashlib, random, json, os

OUT = Path("outputs_quick"); OUT.mkdir(exist_ok=True)

# --- read bits ---
def read_bits():
    bitsf = Path("extracted_bmp.bits")
    if bitsf.exists():
        s = bitsf.read_text().strip()
        return list(s)
    bmp = Path("extracted_bmp.bmp")
    if not bmp.exists():
        raise SystemExit("NO extracted_bmp.bmp ni extracted_bmp.bits en este directorio.")
    img = Image.open(bmp).convert("RGB")
    w,h = img.size
    bits = [ str(img.getpixel((x,y))[2] & 1) for y in range(h) for x in range(w) ]  # blue LSB, top->bottom
    bitsf.write_text("".join(bits))
    print(f"[+] Extracted {len(bits)} bits to extracted_bmp.bits")
    return bits

# --- permutation generators ---
class LCG:
    def __init__(self, seed): 
        self.a,self.c,self.m = 1103515245,12345,2**31
        self.state = seed & (self.m-1)
    def rand(self): 
        self.state = (self.a*self.state + self.c) % self.m
        return self.state
    def randrange(self,n): 
        return self.rand() % n

def shuffle_with(n, rng_type, seed_val):
    arr = list(range(n))
    if rng_type == "python_mt":
        r = random.Random(seed_val)
        r.shuffle(arr)
        return arr
    if rng_type == "lcg":
        rng = LCG(seed_val)
        for i in range(n-1,0,-1):
            j = rng.randrange(i+1)
            arr[i],arr[j] = arr[j],arr[i]
        return arr
    raise ValueError

def invert_perm(p):
    inv=[0]*len(p)
    for i,v in enumerate(p): inv[v]=i
    return inv

def bits_to_bytes(bits, msb=True):
    out = bytearray()
    for i in range(0,len(bits),8):
        chunk = bits[i:i+8]
        if len(chunk) < 8: break
        if msb:
            v=0
            for b in chunk: v=(v<<1)| (1 if b=='1' else 0)
        else:
            v=0
            for j,b in enumerate(chunk):
                if b=='1': v |= (1<<j)
        out.append(v)
    return bytes(out)

def sha256_stream(seed_bytes, nbytes, counter_len=4, counter_endian='big', order='seed_ctr'):
    out = bytearray(); blk=0; maxv = 1 << (counter_len*8)
    while len(out) < nbytes:
        ctr = (blk % maxv).to_bytes(counter_len, counter_endian)
        if order=='seed_ctr':
            out.extend(hashlib.sha256(seed_bytes + ctr).digest())
        else:
            out.extend(hashlib.sha256(ctr + seed_bytes).digest())
        blk += 1
    return bytes(out[:nbytes])

def printable_ratio(data):
    if not data: return 0.0
    return sum(1 for c in data if 32 <= c < 127 or c in (9,10,13)) / len(data)

# --- seeds ---
sf = Path("seeds_found.txt")
if not sf.exists():
    print("No seeds_found.txt — crea uno con la seed (ej: 31415) o ejecuta dark.exe en VM para obtenerla."); raise SystemExit
seeds = [l.strip() for l in sf.read_text().splitlines() if l.strip()]
if not seeds:
    print("seeds_found.txt vacío"); raise SystemExit

bits = read_bits()
n = len(bits)
print(f"[+] bits len = {n}, bytes ≈ {n//8}")

# combos to try (limited set)
rngs = ["python_mt","lcg"]
perm_apps = ["inv_then_bits_at_index","bits_at_perm_index"]
msb_opts = [True, False]
seed_byte_modes = ["str","int4be","int4le","hex"]  # will skip invalid
counter_lens = [4,8]
counter_endians = ["big","little"]
counter_orders = ["seed_ctr","ctr_seed"]

results = []

for seed in seeds:
    # normalized integer for RNG seeding
    try:
        seed_int = int(seed,10)
    except:
        try:
            if seed.lower().startswith("0x"): seed_int = int(seed,16)
            else: seed_int = int(hashlib.sha256(seed.encode()).hexdigest(),16) & 0x7fffffff
        except:
            seed_int = int(hashlib.sha256(seed.encode()).hexdigest(),16) & 0x7fffffff
    # build possible seed bytes
    seed_bytes_list = []
    seed_bytes_list.append(("str", str(seed).encode()))
    if seed.lower().startswith("0x"):
        try:
            seed_bytes_list.append(("hex", bytes.fromhex(seed[2:])))
        except: pass
    try:
        v = int(seed,10)
        seed_bytes_list.append(("int4be", v.to_bytes(4,'big')))
        seed_bytes_list.append(("int4le", v.to_bytes(4,'little')))
    except: pass

    for rng in rngs:
        perm = shuffle_with(n, rng, seed_int)
        inv = invert_perm(perm)
        for perm_app in perm_apps:
            if perm_app == "inv_then_bits_at_index":
                reordered_bits = [ bits[inv[i]] for i in range(n) ]
            else:
                reordered_bits = [ bits[perm[i]] for i in range(n) ]
            for msb in msb_opts:
                data_bytes = bits_to_bytes(reordered_bits, msb)
                if not data_bytes: continue
                # save enc for traceability
                enc_name = f"enc__{seed}__{rng}__{perm_app}__msb{int(msb)}.enc"
                Path(OUT/enc_name).write_bytes(data_bytes)
                for (mode, sbytes) in seed_bytes_list:
                    for ctr_len in counter_lens:
                        for ctr_end in counter_endians:
                            for ctr_order in counter_orders:
                                ks = sha256_stream(sbytes, len(data_bytes), counter_len=ctr_len, counter_endian=ctr_end, order=ctr_order)
                                plain = bytes(a^b for a,b in zip(data_bytes, ks))
                                dec_name = f"dec__{seed}__{rng}__{perm_app}__msb{int(msb)}__{mode}__ctr{ctr_len}{ctr_end}__{ctr_order}.dec"
                                Path(OUT/dec_name).write_bytes(plain)
                                pr = printable_ratio(plain[:1024])
                                magic = None
                                if plain.startswith(b'PK\x03\x04'): magic='zip'
                                if b"flag{" in plain.lower() or pr > 0.75 or magic:
                                    info = {"seed":seed,"rng":rng,"perm_app":perm_app,"msb":msb,"mode":mode,"ctr_len":ctr_len,"ctr_end":ctr_end,"ctr_order":ctr_order,"printable_ratio":pr,"magic":magic}
                                    Path(OUT/(dec_name+".meta.json")).write_text(json.dumps(info,indent=2))
                                    print("[!] candidate saved:", dec_name, "pr=",pr, "magic=",magic)
                                    results.append((dec_name,info))
print("Done. results:", len(results), " -> folder outputs_quick")
if not results:
    print("No obvious candidate found. Recomendado: confirmar seed EXACTA ejecutando dark.exe en VM, o aumentar variantes (col-major, other RNGs, counter sizes).")
