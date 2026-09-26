#!/usr/bin/env python3
# descifra_con_diccionario_mejorado.py
"""
Uso:
  - Coloca tu archivo cifrado en ARCHIVO_ENCRIPTADO.
  - Coloca el diccionario en DICCIONARIO (una passphrase por línea).
  - Ejecuta: python3 descifra_con_diccionario_mejorado.py
Opciones:
  - Cambia TIMEOUT por el tiempo en segundos que quieres esperar por intento.
  - Si quieres ver cada passphrase en stdout, pon VERBOSE = True (poco seguro).
"""

import subprocess
import tempfile
import os
import shutil
import sys
import signal

ARCHIVO_ENCRIPTADO = "flag.txt.gpg"
ARCHIVO_SALIDA = "salida.txt"
DICCIONARIO = "diccionario"
PROGRESO_FILE = ".progreso"   # línea hasta la que ya probamos (0-based)
TIMEOUT = 12                  # segundos por intento
VERBOSE = False               # si True imprime cada passphrase (útil para debugging)
ENCODING = "utf-8"

# limpieza: si interrumpen el script
_temp_files = []
def _cleanup_tempfiles():
    for p in _temp_files:
        try:
            if os.path.exists(p):
                os.remove(p)
        except Exception:
            pass

def _signal_handler(sig, frame):
    print("\nInterrumpido. Limpiando archivos temporales...")
    _cleanup_tempfiles()
    sys.exit(1)

signal.signal(signal.SIGINT, _signal_handler)
signal.signal(signal.SIGTERM, _signal_handler)

def leer_diccionario(ruta):
    with open(ruta, "r", encoding=ENCODING, errors="ignore") as f:
        return [linea.rstrip("\n\r") for linea in f if linea.strip()]

def leer_progreso():
    if not os.path.exists(PROGRESO_FILE):
        return 0
    try:
        with open(PROGRESO_FILE, "r", encoding=ENCODING) as f:
            return int(f.read().strip() or "0")
    except Exception:
        return 0

def guardar_progreso(index):
    tmp = PROGRESO_FILE + ".tmp"
    with open(tmp, "w", encoding=ENCODING) as f:
        f.write(str(index))
    os.replace(tmp, PROGRESO_FILE)

def intentar_descifrar_con_pass(clave, archivo_encriptado, timeout=TIMEOUT):
    """
    Intenta descifrar pasando la passphrase por stdin (fd 0).
    Devuelve (exit_code, ruta_archivo_temporal, stderr).
    """
    # archivo temporal para la salida
    fd, tmpout = tempfile.mkstemp(prefix="gpg_try_", suffix=".out")
    os.close(fd)
    _temp_files.append(tmpout)

    cmd = [
        "gpg",
        "--batch",
        "--yes",
        "--pinentry-mode", "loopback",
        "--passphrase-fd", "0",
        "--output", tmpout,
        "--decrypt", archivo_encriptado
    ]

    try:
        # pasamos la passphrase por stdin (agregamos newline como hace un prompt)
        proc = subprocess.run(
            cmd,
            input=(clave + "\n"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout
        )
    except subprocess.TimeoutExpired:
        # proceso quedó colgado / muy lento
        return (2, tmpout, "Timeout expired")
    except FileNotFoundError:
        _cleanup_tempfiles()
        print("ERROR: no se encontró el ejecutable 'gpg'. Instálalo o asegúrate que esté en PATH.")
        sys.exit(2)
    except Exception as e:
        return (3, tmpout, f"Excepción al ejecutar GPG: {e}")

    return (proc.returncode, tmpout, proc.stderr)

def main():
    if not os.path.exists(ARCHIVO_ENCRIPTADO):
        print(f"ERROR: no existe el archivo cifrado: {ARCHIVO_ENCRIPTADO}")
        sys.exit(1)
    if not os.path.exists(DICCIONARIO):
        print(f"ERROR: no existe el diccionario: {DICCIONARIO}")
        sys.exit(1)

    claves = leer_diccionario(DICCIONARIO)
    total = len(claves)
    inicio = leer_progreso()
    if inicio >= total:
        print("Punto de reanudación indica que ya probaste todas las claves.")
        sys.exit(0)

    print(f"🔍 Probando {total - inicio} claves (desde índice {inicio})...")

    for idx in range(inicio, total):
        clave = claves[idx]
        if VERBOSE:
            print(f"[{idx}/{total}] Probando: '{clave}'")
        else:
            # imprimimos progreso pero sin revelar la clave
            print(f"[{idx+1}/{total}] Probando... ", end="", flush=True)

        code, tmpout, stderr = intentar_descifrar_con_pass(clave, ARCHIVO_ENCRIPTADO)
        # guardar progreso (siempre que no sea un fallo "inestable")
        guardar_progreso(idx + 1)

        if code == 0:
            # éxito: validar que el archivo temporal tiene contenido razonable
            try:
                size = os.path.getsize(tmpout)
            except Exception:
                size = 0
            if size == 0:
                # fallo inesperado, tratar como no exitoso
                print("Fallo: salida está vacía. Continuando.")
                _temp_files.remove(tmpout)
                try:
                    os.remove(tmpout)
                except Exception:
                    pass
                continue

            # mover el archivo temporal a la salida final
            shutil.move(tmpout, ARCHIVO_SALIDA)
            if tmpout in _temp_files:
                _temp_files.remove(tmpout)
            print("✅ Clave correcta encontrada!")
            if VERBOSE:
                print(f"Clave: {clave}")
            else:
                print(f"Clave encontrada en índice {idx+1}/{total}")
            print(f"Resultado guardado en: {ARCHIVO_SALIDA}\n")
            # opcional: mostrar contenido (puede ser binario)
            try:
                with open(ARCHIVO_SALIDA, "r", encoding=ENCODING, errors="replace") as f:
                    contenido = f.read()
                    print("----- CONTENIDO (preview) -----")
                    print(contenido[:10_000])  # show up to 10k chars
                    print("----- FIN PREVIEW -----")
            except Exception:
                print("(No se puede mostrar contenido como texto; podría ser binario.)")
            _cleanup_tempfiles()
            return

        else:
            # no fue exit code 0 -> fallo (Bad session key, cancel, etc.)
            if VERBOSE:
                print(f" -> returncode={code}. stderr:\n{stderr}")
            else:
                print("Falló.")
            # borrar tmpout si existe
            if tmpout in _temp_files:
                _temp_files.remove(tmpout)
            try:
                if os.path.exists(tmpout):
                    os.remove(tmpout)
            except Exception:
                pass
            # continuar con la siguiente clave

    print("\n❌ No se encontró ninguna clave válida en el diccionario.")
    _cleanup_tempfiles()

if __name__ == "__main__":
    main()
