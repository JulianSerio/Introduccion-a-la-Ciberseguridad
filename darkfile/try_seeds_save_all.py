#!/usr/bin/env python3
# try_seeds_save_all.py
# Guarda TODOS los intentos (enc + dec + metadata) en outputs_all/
from pathlib import Path
import hashlib, random, json, csv
from PIL import Image

OUTDIR = Path("outputs_all")
OUTDIR.mkdir(exist_ok=True)

# --- helpers ---
def read_bits():
    bits_path = Path("extracted_bmp.bits")
    if bits_path.exists():
        s = bits_path.read_text().strip()
        return list(s)
    bmp = Path("extracted_bmp.bmp")
    if bmp.exists():
        img = Image.open(bmp).convert("RGB")
        w,h = img.size
        bits = [ str(img.getpixel((x,y))[2]&1) for y in range(h) for x in range(w) ]
        bits_path.write_text("".join(bits))
        print(f"[+] Extracted {len(bits)} bits to extracted_bmp.bits")
        return list(bits)
    raise SystemExit("No extracted_bmp.bits ni extracted_bmp.bmp en el directorio.")

def seed_to_int_safe(seed):
    s = str(seed)
    try:
        return int(s,10)
    except Exception:
        try:
            if s.lower().startswith("0x"):
                return int(s,16)
        except Exception:
            pass
    return int(hashlib.sha256(s.encode()).hexdigest(),16) & 0x7fffffff

def seed_to_bytes_variants(seed):
    s = str(seed)
    lst = []
    lst.append(("str", s.encode()))
    if s.lower().startswith("0x"):
        try:
            lst.append(("hex", bytes.fromhex(s[2:])))
        except:
            pass
    try:
        v = int(s,0)
        lst.append(("int4be", v.to_bytes(4,'big', signed=False)))
        lst.append(("int4le", v.to_bytes(4,'little', signed=False)))
        lst.append(("int8be", v.to_bytes(8,'big', signed=False)))
        lst.append(("int8le", v.to_bytes(8,'little', signed=False)))
    except:
        pass
    return lst

class LCG:
    def __init__(self, seed):
        self.a,self.c,self.m = 1103515245,12345,2**31
        self.state = seed & (self.m-1)
    def rand(self):
        self.state = (self.a*self.state + self.c) % self.m
        return self.state
    def randrange(self,n):
        return self.rand() % n

def shuffle_with_rng(n, rng_type, seed_value):
    arr = list(range(n))
    if rng_type == "python_mt":
        r = random.Random(seed_value)
        r.shuffle(arr)
        return arr
    if rng_type == "lcg":
        rng = LCG(seed_value)
        for i in range(n-1,0,-1):
            j = rng.randrange(i+1)
            arr[i],arr[j] = arr[j],arr[i]
        return arr
    raise ValueError("rng_type unknown")

def invert_perm(p):
    inv = [0]*len(p)
    for i,v in enumerate(p): inv[v]=i
    return inv

def bits_to_bytes(bitlist, msb_first=True):
    out = bytearray()
    for i in range(0,len(bitlist),8):
        chunk = bitlist[i:i+8]
        if len(chunk) < 8: break
        if msb_first:
            v = 0
            for b in chunk: v = (v<<1) | (1 if b == '1' else 0)
        else:
            v = 0
            for j,b in enumerate(chunk):
                if b == '1': v |= (1<<j)
        out.append(v)
    return bytes(out)

def sha256_keystream(seed_bytes, nbytes, counter_len=4, counter_endian='big', order='seed_ctr'):
    out = bytearray()
    blk = 0
    maxv = 1 << (counter_len*8)
    while len(out) < nbytes:
        ctr = (blk % maxv).to_bytes(counter_len, counter_endian)
        if order == 'seed_ctr':
            out.extend(hashlib.sha256(seed_bytes + ctr).digest())
        else:
            out.extend(hashlib.sha256(ctr + seed_bytes).digest())
        blk += 1
    return bytes(out[:nbytes])

def detect_magic(data):
    mags = {
        b'PK\x03\x04':'zip', b'\x1f\x8b':'gzip', b'\x89PNG':'png',
        b'%PDF-':'pdf', b'BZh':'bzip2', b'\xff\xd8\xff':'jpg'
    }
    for k,v in mags.items():
        if data.startswith(k): return v
    return None

def printable_ratio(data):
    if not data: return 0.0
    good = sum(1 for c in data if 32 <= c < 127 or c in (9,10,13))
    return good / len(data)

# --- main pipeline ---
bits = read_bits()
nbits = len(bits)
print(f"[+] Bits loaded: {nbits} ({nbits//8} bytes approx)")

seeds_file = Path("seeds_found.txt")
if not seeds_file.exists():
    raise SystemExit("No encontre seeds_found.txt")
seeds = [l.strip() for l in seeds_file.read_text().splitlines() if l.strip()]
if not seeds:
    raise SystemExit("seeds_found.txt vacío")

# combos to try (feel free to edit here)
rng_types = ["python_mt","lcg"]
perm_apps = ["inv_then_bits_at_index","bits_at_perm_index"]
msb_opts = [True, False]
seed_byte_modes = None  # will be built per-seed
counter_lens = [4,8]    # try 4 and 8
counter_orders = ["seed_ctr","ctr_seed"]
counter_endians = ["big","little"]

# CSV summary header
summary_path = OUTDIR/"summary.csv"
with open(summary_path,"w",newline="") as csvf:
    csvw = csv.writer(csvf)
    csvw.writerow(["filename_enc","filename_dec","seed","rng","perm_app","msb","seed_mode","counter_len","counter_endian","counter_order","bytes","printable_ratio","magic"])

total = 0
for seed in seeds:
    seed_int = seed_to_int_safe(seed)
    seed_bytes_list = seed_to_bytes_variants(seed)
    for rng in rng_types:
        perm = shuffle_with_rng(nbits, rng, seed_int)
        inv = invert_perm(perm)
        for perm_app in perm_apps:
            if perm_app == "inv_then_bits_at_index":
                reordered_bits = [ bits[inv[i]] for i in range(nbits) ]
            else:
                reordered_bits = [ bits[perm[i]] for i in range(nbits) ]
            for msb in msb_opts:
                data_bytes = bits_to_bytes(reordered_bits, msb_first=msb)
                if not data_bytes:
                    continue
                # save enc file
                fname_enc = f"enc__{seed}__{rng}__{perm_app}__msb{int(msb)}.enc"
                fpath_enc = OUTDIR / fname_enc
                fpath_enc.write_bytes(data_bytes)
                # now for each seed_bytes variant and counter variants produce dec files
                for (mode, sbytes) in seed_bytes_list:
                    for ctr_len in counter_lens:
                        for ctr_end in counter_endians:
                            for ctr_order in counter_orders:
                                ks = sha256_keystream(sbytes, len(data_bytes), counter_len=ctr_len, counter_endian=ctr_end, order=ctr_order)
                                plain = bytes(a^b for a,b in zip(data_bytes, ks))
                                fname_dec = f"dec__{seed}__{rng}__{perm_app}__msb{int(msb)}__{mode}__ctr{ctr_len}{ctr_end}__{ctr_order}.dec"
                                fpath_dec = OUTDIR / fname_dec
                                fpath_dec.write_bytes(plain)
                                # metadata & summary
                                magic = detect_magic(plain[:8])
                                pr = printable_ratio(plain[:1024])
                                meta = {
                                    "seed": seed, "rng": rng, "perm_app": perm_app, "msb": msb,
                                    "seed_mode": mode, "counter_len": ctr_len, "counter_endian": ctr_end,
                                    "counter_order": ctr_order, "bytes": len(plain), "printable_ratio": pr, "magic": magic
                                }
                                Path(str(fpath_dec)+".meta.json").write_text(json.dumps(meta, indent=2))
                                with open(summary_path,"a",newline="") as csvf:
                                    csvw = csv.writer(csvf)
                                    csvw.writerow([fname_enc, fname_dec, seed, rng, perm_app, int(msb), mode, ctr_len, ctr_end, ctr_order, len(plain), f"{pr:.4f}", magic or ""])
                                total += 1
    print(f"[+] Seed {seed}: attempts so far total={total}")

print(f"[+] FINISHED. Total attempts: {total}. All files in {OUTDIR}, summary at {summary_path}")
