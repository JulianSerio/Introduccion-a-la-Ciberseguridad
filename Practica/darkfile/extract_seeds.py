#!/usr/bin/env python3
# Extrae seeds de dark.exe y las guarda en seeds_found.txt
import re
from pathlib import Path

data = Path('dark.exe').read_bytes()
cands = set()
for m in re.finditer(rb'\b0x[0-9A-Fa-f]{6,16}\b', data):
    cands.add(m.group(0).decode())
for m in re.finditer(rb'\b\d{2,12}\b', data):
    cands.add(m.group(0).decode())
for m in re.finditer(rb'(?i)seed[:=\s]*([0-9A-Fa-fxX]+)', data):
    cands.add(m.group(1).decode(errors='ignore'))
Path('seeds_found.txt').write_text("\n".join(cands))
print(f"Seeds guardadas ({len(cands)}): seeds_found.txt")
