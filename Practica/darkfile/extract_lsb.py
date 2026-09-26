#!/usr/bin/env python3
# Extrae LSB azul de extracted_bmp.bmp → extracted_bmp.bits
from PIL import Image
from pathlib import Path

bmp_path = Path('extracted_bmp.bmp')
img = Image.open(bmp_path).convert('RGB')
w,h = img.size
bits = [str(img.getpixel((x,y))[2]&1) for y in range(h) for x in range(w)]
Path('extracted_bmp.bits').write_text("".join(bits))
print(f"{len(bits)} bits extraídos -> extracted_bmp.bits")
