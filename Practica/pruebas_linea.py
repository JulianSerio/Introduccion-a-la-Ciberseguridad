#!/usr/bin/env python3
from pathlib import Path
t=Path('archivo.txt').read_text(errors='ignore').splitlines()
target='last warning'
counts=[line.lower().count(target) for line in t]
for i,c in enumerate(counts[:200]): print(f"{i+1:04d}: {c}")
# intentar ASCII decimal de counts no nulos
chars=[chr(c) for c in counts if 0<c<256]
print("\nASCII from counts (first 200 chars):")
print(''.join(chars[:200]))
# paridad->bits
bits=''.join('1' if (c%2)==1 else '0' for c in counts if c>=0)
if len(bits)>=8:
    out=bytes(int(bits[i:i+8],2) for i in range(0,len(bits)-7,8))
    print("\nParity-decoded (utf-8 replace):")
    print(out.decode('utf-8',errors='replace')[:800])
