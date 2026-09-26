import struct
from pathlib import Path
p = Path('dark.exe')
data = p.read_bytes()
off = 0x223ab4
if data[off:off+2] != b'BM':
    print("No BMP en ese offset")
else:
    size = struct.unpack_from('<I', data, off+2)[0]
    out = Path('extracted_bmp.bmp')
    out.write_bytes(data[off:off+size])
    print("BMP extraído:", out, "tamaño:", size)

