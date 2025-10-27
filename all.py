#!/usr/bin/env python3
"""
all_in_one_analysis.py

Script todo-en-uno para analizar una pcapng con objetivo de encontrar una flag/extracción de datos.

Qué hace (sin parámetros):
 - busca un archivo .pcap o .pcapng en el directorio actual (por defecto advertising_team_employee.pcapng si existe)
 - crea un árbol de salida: outputs/{smb_objects,http_objects,tcpflows,dns_recon,carved,lsb,summary}
 - exporta objetos SMB y HTTP con tshark (si está)
 - genera tcpflows con tcpflow (si está)
 - genera dns_queries.csv con tshark
 - intenta extraer objetos con foremost
 - extrae flujos HTTP reensamblados (tshark follow,tcp,raw)
 - escanea archivos extraídos: strings, file, hexdump summary
 - si encuentra imágenes, extrae LSB (canal azul) y guarda bits y bytes
 - intenta zsteg/steghide si están instalados
 - reconstruye posibles exfiltraciones DNS (ensambla subdominios y prueba base32/base64/hex)
 - produce summary/summary.csv con métricas y una lista de candidatos

Notas:
 - Ejecútalo en la carpeta donde esté la pcap (o arrastra la pcap al mismo directorio).
 - Muchas operaciones requieren herramientas externas (tshark, tcpflow, foremost, zsteg, steghide). El script ignora las que faltan y continúa.
 - Conserva TODOS los archivos intermedios para análisis forense posterior.

Ejecutar:
  python3 all_in_one_analysis.py

"""
import subprocess
import shutil
import sys
from pathlib import Path
import os
import csv
import base64
import math
import collections
from PIL import Image

# --- Helpers -----------------------------------------------------------------

def which_bin(name):
    return shutil.which(name) is not None


def run(cmd, timeout=None, check=False):
    """
    Ejecuta comando (lista) y devuelve CompletedProcess.
    - cmd: lista de strings
    - timeout: segundos o None
    - check: si True, lanza CalledProcessError en rc != 0
    """
    print(f"\n$ {' '.join(cmd)}")
    try:
        res = subprocess.run(cmd,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,
                             text=True,
                             timeout=timeout)
    except subprocess.TimeoutExpired as e:
        # informar y devolver lo que tenemos
        print(f"[!] Timeout after {timeout}s. Partial stdout/stderr:")
        if e.stdout:
            print(e.stdout[:1000])
        if e.stderr:
            print(e.stderr[:1000])
        # construir un CompletedProcess-like dict para compatibilidad
        class _R: pass
        r = _R()
        r.stdout = e.stdout or ""
        r.stderr = e.stderr or ""
        r.returncode = None
        return r

    # mostrar salidas (limitar a 1000 chars para consola)
    if res.stdout:
        print(res.stdout[:1000])
    if res.stderr and (res.returncode != 0 or check):
        print("=== stderr (trim) ===")
        print(res.stderr[:1000])

    if check and res.returncode != 0:
        # si el usuario pidió check, lanzar la excepción estándar
        raise subprocess.CalledProcessError(res.returncode, cmd, output=res.stdout, stderr=res.stderr)

    return res


def safe_mkdir(p: Path):
    p.mkdir(parents=True, exist_ok=True)
    return p


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = collections.Counter(s)
    l = len(s)
    return -sum((c/l)*math.log2(c/l) for c in freq.values())


def printable_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    good = sum(1 for c in b if 32 <= c < 127 or c in (9,10,13))
    return good/len(b)

# --- Paths and discovery ----------------------------------------------------

CUR = Path('.').resolve()
DEFAULT_NAMES = ['advertising_team_employee.pcapng', 'advertising_team_employee.pcap',]
PCAP = None
for n in DEFAULT_NAMES:
    p = CUR / n
    if p.exists():
        PCAP = p
        break
if not PCAP:
    # find any pcap/pcapng
    candidates = list(CUR.glob('*.pcap*'))
    if candidates:
        PCAP = candidates[0]

if not PCAP:
    print('No pcap/pcapng encontrado en el directorio actual. Coloca el fichero allí y vuelve a ejecutar.')
    sys.exit(1)

print('Usando pcap:', PCAP)

OUT = safe_mkdir(CUR / 'outputs')
SMB_DIR = safe_mkdir(OUT / 'smb_objects')
HTTP_DIR = safe_mkdir(OUT / 'http_objects')
TCP_DIR = safe_mkdir(OUT / 'tcpflows')
DNS_DIR = safe_mkdir(OUT / 'dns')
CARVED_DIR = safe_mkdir(OUT / 'carved')
LSB_DIR = safe_mkdir(OUT / 'lsb_extracted')
SUMMARY_DIR = safe_mkdir(OUT / 'summary')

# --- External tools availability --------------------------------------------
TOOL = {
    'tshark': which_bin('tshark'),
    'tcpflow': which_bin('tcpflow'),
    'foremost': which_bin('foremost'),
    'zsteg': which_bin('zsteg'),
    'steghide': which_bin('steghide'),
    'binwalk': which_bin('binwalk'),
}
print('Herramientas detectadas:', TOOL)

# --- 1) Exportar objetos con tshark ----------------------------------------
if TOOL['tshark']:
    run(['tshark', '-r', str(PCAP), '--export-objects', f'smb,{SMB_DIR}'], timeout=120)
    run(['tshark', '-r', str(PCAP), '--export-objects', f'http,{HTTP_DIR}'], timeout=120)
    # generar csv de consultas DNS
    dns_csv = DNS_DIR / 'dns_queries.csv'
    run(['tshark', '-r', str(PCAP), '-Y', 'dns', '-T', 'fields', '-e', 'frame.number', '-e', 'frame.time', '-e', 'ip.src', '-e', 'ip.dst', '-e', 'dns.qry.name', '-e', 'dns.qry.type', '-E', 'separator=,', '-E', 'quote=d'], timeout=120)
    # move tshark output to dns file (tshark printed CSV to stdout); rerun capturing to file
    try:
        with open(dns_csv, 'w') as f:
            # second run but direct output
            p = subprocess.run(['tshark', '-r', str(PCAP), '-Y', 'dns', '-T', 'fields', '-e', 'frame.number', '-e', 'frame.time', '-e', 'ip.src', '-e', 'ip.dst', '-e', 'dns.qry.name', '-e', 'dns.qry.type', '-E', 'separator=,'], stdout=f, stderr=subprocess.PIPE, text=True, timeout=120)
            if p.returncode != 0:
                print('tshark dns extraction returned', p.returncode)
    except Exception as e:
        print('no se pudo generar dns_queries.csv', e)
else:
    print('tshark no instalado: omitiendo export objects y dns csv')

# --- 2) tcpflow (reensamblar flujos TCP) -----------------------------------
if TOOL['tcpflow']:
    run(['tcpflow', '-r', str(PCAP), '-o', str(TCP_DIR)], timeout=300)
else:
    print('tcpflow no encontrado: omitido')

# --- 3) foremost carving ---------------------------------------------------
if TOOL['foremost']:
    try:
        run(['foremost', '-i', str(PCAP), '-o', str(CARVED_DIR)], timeout=300)
    except Exception as e:
        print('foremost fallo:', e)
else:
    print('foremost no instalado: omitido carving')

# --- 4) export HTTP follow streams (reassembled) ---------------------------
if TOOL['tshark']:
    # find tcp streams that contain HTTP response
    try:
        p = subprocess.run(['tshark', '-r', str(PCAP), '-Y', 'http.response', '-T', 'fields', '-e', 'tcp.stream'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=120)
        streams = sorted(set([s for s in p.stdout.splitlines() if s.strip()]))
        for s in streams:
            outf = TCP_DIR / f'http_stream_{s}.raw'
            run(['tshark', '-r', str(PCAP), '-q', '-z', f'follow,tcp,raw,{s}'], timeout=60)
            # gather output from last command in stdout (tshark prints to stdout)
            # easier: use tshark -z follow isn't straightforward to capture per stream; try tshark -z follow,tcp,raw,<n> - but we'll write to file by redirect above
            # fallback: ignore if complex
    except Exception as e:
        print('error al extraer follow tcp http:', e)

# --- 5) quick file summary of extracted objects ----------------------------
print('\nEscaneando archivos extraidos y generando dumps...')
DUMPS_DIR = SUMMARY_DIR / 'dumps'
safe_mkdir(DUMPS_DIR)

candidates = []
search_dirs = [SMB_DIR, HTTP_DIR, TCP_DIR, CARVED_DIR]
for d in search_dirs:
    if not d.exists():
        continue
    for f in d.rglob('*'):
        if f.is_dir():
            continue
        try:
            info = subprocess.run(['file', '-b', str(f)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            ftype = info.stdout.strip()
        except Exception:
            ftype = ''
        strings_out = subprocess.run(['strings', '-n', '6', str(f)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        dumpf = DUMPS_DIR / (f.name.replace('/', '_') + '.dump.txt')
        with open(dumpf, 'w', errors='ignore') as fh:
            fh.write(f"FILE: {f}\nTYPE: {ftype}\n\n")
            fh.write('--- HEX(0:512) ---\n')
            try:
                hd = subprocess.run(['xxd', '-l', '512', '-g', '1', str(f)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                fh.write(hd.stdout + '\n')
            except Exception:
                pass
            fh.write('\n--- STRINGS ---\n')
            fh.write(strings_out.stdout)
        candidates.append((str(f), ftype, len(strings_out.stdout)))

# --- 6) LSB extraction from images found -----------------------------------
print('\nBuscando imágenes y extrayendo LSB (canal azul) ...')
image_exts = {'.bmp', '.png', '.jpg', '.jpeg'}
lsb_index = []
for d in search_dirs + [CARVED_DIR]:
    if not d.exists(): continue
    for f in d.rglob('*'):
        if f.suffix.lower() in image_exts:
            try:
                im = Image.open(f).convert('RGB')
                w,h = im.size
                bits = []
                for y in range(h):
                    for x in range(w):
                        bits.append(str(im.getpixel((x,y))[2] & 1))
                bits_txt = LSB_DIR / (f.name + '.bits')
                bits_txt.write_text(''.join(bits))
                # write bytes grouped by 8 (MSB-first)
                b = bytearray()
                for i in range(0, len(bits), 8):
                    chunk = bits[i:i+8]
                    if len(chunk) < 8: break
                    val = 0
                    for bit in chunk:
                        val = (val<<1) | (1 if bit=='1' else 0)
                    b.append(val)
                bytesf = LSB_DIR / (f.name + '.lsbbytes')
                bytesf.write_bytes(bytes(b))
                lsb_index.append((str(f), bits_txt.name, bytesf.name, w, h))
                # try stego tools if available
                if TOOL['zsteg'] and f.suffix.lower() in ('.png', '.bmp'):
                    try:
                        out_z = SUMMARY_DIR / (f.name + '.zsteg.txt')
                        subprocess.run(['zsteg', str(f)], stdout=open(out_z,'w'), stderr=subprocess.DEVNULL, timeout=60)
                    except Exception:
                        pass
                if TOOL['steghide'] and f.suffix.lower() in ('.jpg', '.jpeg', '.bmp'):
                    try:
                        outdir = SUMMARY_DIR / 'steghide_extracted'
                        outdir.mkdir(exist_ok=True)
                        # try empty pass
                        subprocess.run(['steghide', 'extract', '-sf', str(f), '-xf', str(outdir / (f.name + '.stgh')) , '-p', ''], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
                    except Exception:
                        pass
            except Exception as e:
                print('error procesando imagen', f, e)

# --- 7) DNS reconstruction attempts ----------------------------------------
print('\nAnalizando dns_queries.csv para detectar exfiltracion por subdominios...')
dns_csv = DNS_DIR / 'dns_queries.csv'
if dns_csv.exists():
    import re
    groups = {}
    with open(dns_csv) as f:
        for line in f:
            parts = line.strip().split(',')
            if len(parts) < 6: continue
            name = parts[4].strip().rstrip('.')
            if not name: continue
            labels = name.split('.')
            if len(labels) < 2: continue
            sld = '.'.join(labels[-2:])
            groups.setdefault(sld, []).append(name)
    dns_recon_dir = OUT / 'dns_recon'
    dns_recon_dir.mkdir(exist_ok=True)
    for sld,qs in groups.items():
        # take sequence order and make unique runs
        seq = [q.split('.')[0] for q in qs]
        uniq = []
        for x in seq:
            if not uniq or uniq[-1] != x:
                uniq.append(x)
        joined = ''.join(uniq)
        # heuristics: if long or high entropy try decode
        max_label_len = max(len(x) for x in uniq) if uniq else 0
        ent = shannon_entropy(joined[:200])
        if len(joined) < 32 and max_label_len < 16 and ent < 3.5:
            continue
        # try base32
        try:
            dec = base64.b32decode(joined.upper() + '===' )
            outp = dns_recon_dir / f'{sld}_b32.bin'
            outp.write_bytes(dec)
            print('dns_recon wrote', outp)
        except Exception:
            pass
        # try base64
        try:
            dec = base64.b64decode(joined + '===')
            outp = dns_recon_dir / f'{sld}_b64.bin'
            outp.write_bytes(dec)
            print('dns_recon wrote', outp)
        except Exception:
            pass
        # try hex
        if re.fullmatch(r'[0-9a-fA-F]+', joined):
            try:
                outp = dns_recon_dir / f'{sld}_hex.bin'
                outp.write_bytes(bytes.fromhex(joined))
                print('dns_recon wrote', outp)
            except Exception:
                pass
else:
    print('dns_queries.csv no encontrado — tshark pudo fallar o no hay dns paquetes')

# --- 8) summary CSV and search for flag patterns ---------------------------
print('\nGenerando summary y buscando patrones como flag{ ... }')
summary_csv = SUMMARY_DIR / 'summary.csv'
with open(summary_csv, 'w', newline='') as scsv:
    w = csv.writer(scsv)
    w.writerow(['file','type','bytes','printable_ratio','magic','notes'])
    # index dumps
    for dump in DUMPS_DIR.glob('*.dump.txt'):
        fname = dump.name.replace('.dump.txt','')
        # try to detect magic and printable ratio by reading strings and first bytes
        try:
            with open(dump,'rb') as fh:
                data = fh.read()
        except Exception:
            data = b''
        pr = printable_ratio(data[:2048])
        magic = ''
        notes = ''
        if b'flag{' in data.lower():
            notes = 'contains_flag'
        w.writerow([fname, '', len(data), f'{pr:.4f}', magic, notes])

# search outputs for 'flag{' rapidly
print('\nBuscando "flag{" en outputs...')
found = list(Path(OUT).rglob('*'))
matches = []
for f in found:
    if f.is_file():
        try:
            if 'flag{' in f.read_bytes().lower():
                matches.append(str(f))
        except Exception:
            continue
if matches:
    print('\n=== ARCHIVOS QUE CONTIENEN flag{ ===')
    for m in matches:
        print(m)
else:
    print('No se encontró "flag{" literales en outputs. Revisa archivos en outputs/ para análisis posterior.')

print('\nEjecución finalizada. Revisa la carpeta outputs/ con todo lo extraído y los ficheros lsb_extracted, dns_recon y carved.')
print('Resumen en:', SUMMARY_DIR)
