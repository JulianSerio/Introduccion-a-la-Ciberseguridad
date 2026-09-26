#!/usr/bin/env python3
"""
analyze_dotnet_artifacts.py
Analiza DLL/.pdb/.deps.json/.runtimeconfig.json en el directorio actual y genera
un reporte completo en outputs_dotnet/.

Uso:
  python3 analyze_dotnet_artifacts.py

Requisitos opcionales:
  - ilspycmd (dotnet tool) -> decompila DLLs (se usa si está disponible)
  - file, strings, xxd, sha256sum, sha512sum (herramientas comunes en Linux)
El script funciona sin ellos, pero usa lo que encuentre.
"""
from pathlib import Path
import subprocess, shutil, json, sys, hashlib, base64, datetime

HERE = Path.cwd()
OUT = HERE / "outputs_dotnet"
DECOMP = OUT / "decompiled"
DUMPS = OUT / "dumps"
STRINGS = OUT / "strings"
META = OUT / "meta"
OUT.mkdir(exist_ok=True)
DECOMP.mkdir(exist_ok=True)
DUMPS.mkdir(exist_ok=True)
STRINGS.mkdir(exist_ok=True)
META.mkdir(exist_ok=True)

# Tools detection
HAS = {
    "ilspycmd": shutil.which("ilspycmd") is not None,
    "file": shutil.which("file") is not None,
    "strings": shutil.which("strings") is not None,
    "xxd": shutil.which("xxd") is not None,
    "sha256sum": shutil.which("sha256sum") is not None,
    "sha512sum": shutil.which("sha512sum") is not None,
}

SENSITIVE = ["flag{", "ctf{", "password", "passwd", "secret", "token", "api_key", "apikey", "key", "seed", "private", "ssh-rsa"]

def run(cmd, timeout=300):
    """Run command, return (rc, stdout, stderr)."""
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "TIMEOUT"

def hash_file(path):
    """Return (sha256_hex, sha512_base64)"""
    with open(path, "rb") as f:
        data = f.read()
    sha256 = hashlib.sha256(data).hexdigest()
    sha512_b64 = base64.b64encode(hashlib.sha512(data).digest()).decode()
    return sha256, sha512_b64

def dump_basic_info(fpath):
    meta = {}
    meta["path"] = str(fpath)
    meta["size"] = fpath.stat().st_size
    meta["mtime"] = datetime.datetime.utcfromtimestamp(fpath.stat().st_mtime).isoformat() + "Z"
    if HAS["file"]:
        rc, out, err = run(["file", "-b", str(fpath)])
        meta["file"] = out.strip()
    else:
        meta["file"] = ""
    if HAS["xxd"]:
        rc, out, err = run(["xxd", "-l", "256", "-g", "1", str(fpath)])
        meta["hexdump_first256"] = out
    else:
        meta["hexdump_first256"] = ""
    sha256, sha512_b64 = hash_file(fpath)
    meta["sha256"] = sha256
    meta["sha512_b64"] = sha512_b64
    return meta

def extract_strings(fpath, min_len=4):
    if HAS["strings"]:
        _, out, _ = run(["strings", "-n", str(min_len), str(fpath)])
        return out.splitlines()
    else:
        # fallback naive: read ascii bytes runs
        out = []
        try:
            data = fpath.read_bytes()
            cur = bytearray()
            for b in data:
                if 32 <= b < 127:
                    cur.append(b)
                else:
                    if len(cur) >= min_len:
                        out.append(cur.decode(errors="ignore"))
                    cur = bytearray()
            if len(cur) >= min_len:
                out.append(cur.decode(errors="ignore"))
        except Exception:
            pass
        return out

def search_sensitive(lines):
    hits = []
    low = [s.lower() for s in SENSITIVE]
    for i,ln in enumerate(lines):
        lnl = ln.lower()
        for token in low:
            if token in lnl:
                hits.append((i+1, token, ln))
                break
    return hits

def decompile_ilspy(dll, outdir):
    """Run ilspycmd -p dll -o outdir if available"""
    if not HAS["ilspycmd"]:
        return False, "ilspycmd not found"
    outdir.mkdir(parents=True, exist_ok=True)
    cmd = ["ilspycmd", "-p", str(dll), "-o", str(outdir)]
    rc, out, err = run(cmd, timeout=600)
    ok = (rc == 0)
    return ok, out + ("\nERR:\n"+err if err else "")

# main
report_lines = []
report_lines.append(f"DotNet artifact analysis report - {datetime.datetime.utcnow().isoformat()}Z\n")
report_lines.append(f"Working dir: {str(HERE)}\n")
report_lines.append(f"Output dir: {str(OUT)}\n\n")

# locate files
dlls = list(HERE.glob("*.dll"))
pdbs = list(HERE.glob("*.pdb"))
deps = list(HERE.glob("*.deps.json"))
runtimes = list(HERE.glob("*runtimeconfig*.json"))

report_lines.append(f"Found {len(dlls)} dll(s), {len(pdbs)} pdb(s), {len(deps)} deps.json, {len(runtimes)} runtimeconfig.json\n\n")

# write meta summary
meta_index = {"dlls": [], "pdbs": [], "deps": [], "runtimeconfig": []}

for d in dlls:
    meta = dump_basic_info(d)
    meta_index["dlls"].append(meta)
    # save meta json
    (META / (d.name + ".meta.json")).write_text(json_pretty := json.dumps(meta, indent=2))

for p in pdbs:
    meta = dump_basic_info(p)
    meta_index["pdbs"].append(meta)
    (META / (p.name + ".meta.json")).write_text(json.dumps(meta, indent=2))

for dp in deps:
    try:
        data = json.loads(dp.read_text())
    except Exception:
        data = dp.read_text()
    meta_index["deps"].append({"path": str(dp), "content_preview": str(data)[:400]})
    (META / (dp.name + ".copy")).write_text(dp.read_text())

for r in runtimes:
    try:
        data = json.loads(r.read_text())
    except Exception:
        data = r.read_text()
    meta_index["runtimeconfig"].append({"path": str(r), "content_preview": str(data)[:400]})
    (META / (r.name + ".copy")).write_text(r.read_text())

# analyze each dll
for d in dlls:
    report_lines.append(f"--- DLL: {d.name} ---\n")
    report_lines.append(f"path: {d.resolve()}\n")
    meta = dump_basic_info(d)
    report_lines.append(f"file type: {meta.get('file','')}\n")
    report_lines.append(f"size: {meta.get('size')}, sha256: {meta.get('sha256')}\n")
    # strings
    s_lines = extract_strings(d, min_len=4)
    sfile = STRINGS / (d.name + ".strings.txt")
    sfile.write_text("\n".join(s_lines))
    report_lines.append(f"extracted {len(s_lines)} string lines -> {sfile}\n")
    # search sensitive tokens
    hits = search_sensitive(s_lines)
    if hits:
        report_lines.append("Sensitive hits in strings:\n")
        for ln, token, txt in hits[:200]:
            report_lines.append(f"  line {ln}: token={token} -> {txt}\n")
    else:
        report_lines.append("No obvious sensitive tokens in strings.\n")
    # attempt decompile
    if HAS["ilspycmd"]:
        dec_out = DECOMP / d.stem
        ok, out = decompile_ilspy(d, dec_out)
        if ok:
            report_lines.append(f"Decompiled with ilspycmd -> {dec_out}\n")
        else:
            report_lines.append(f"ilspycmd failed or not available: {out}\n")
    else:
        report_lines.append("ilspycmd not found -> skipping decompilation (install dotnet tool ilspycmd to decompile)\n")
    report_lines.append("\n")

# Save a friendly JSON index
(META / "index.json").write_text(json.dumps(meta_index, indent=2))

# Create a compact human-readable report file
report_file = OUT / "report.txt"
with open(report_file, "w") as rf:
    rf.write("\n".join(report_lines))

print("Analysis complete.")
print("Outputs written to:", OUT)
print(" - meta files:", META)
print(" - strings: ", STRINGS)
print(" - decompiled (if ilspycmd available):", DECOMP)
print(" - high-level report:", report_file)
print()
print("Next suggestions:")
print(" - If decompiled code exists in outputs, search for hardcoded secrets or suspicious network/cipher code.")
print(" - If you want, pega aquí el 'report.txt' o algún archivo de outputs/ y te ayudo a interpretar resultados.")
