#!/usr/bin/env python3

import subprocess
import socket

# Configuración fija (ajustala si es necesario)
CLAVE_PUBLICA = "publica.gpg"
ARCHIVO_A_ENCRIPTAR = "encriptar.txt"
ARCHIVO_ENCRIPTADO = "encriptado.asc"
HOST = "ic.catedras.linti.unlp.edu.ar"
PORT = 12003

# 1. Importar clave pública (si no estaba)
subprocess.run(["gpg", "--import", CLAVE_PUBLICA], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# 2. Obtener fingerprint de la clave importada
#--with-colons da la información en un formato fácil de parsear"
#--fingerprint muestra el fingerprint"
#capture_output=True captura stdout y stderr"
#texto=True decodifica a string"
res = subprocess.run(["gpg", "--with-colons", "--fingerprint"], capture_output=True, text=True)
"busca la linea que comienza con 'fpr:' y toma la 10ma columna (índice 9)"
fpr = next((line.split(":")[9] 
        for line in res.stdout.splitlines() 
            if line.startswith("fpr:")), None)
print(f"Fingerprint de la clave importada: {fpr}")
if not fpr:
    print("❌ No se pudo obtener el fingerprint de la clave.")
    exit(1)

# 3. Encriptar el archivo en modo ASCII (texto plano)
cmd = ["gpg", "--yes", "--armor", "--output", ARCHIVO_ENCRIPTADO, "--encrypt", "--recipient", fpr, ARCHIVO_A_ENCRIPTAR]
subprocess.run(cmd, check=True)

# 4. Leer el archivo encriptado
with open(ARCHIVO_ENCRIPTADO, "rb") as f:
    data = f.read()

# 5. Enviar al servidor usando sockets
with socket.create_connection((HOST, PORT), timeout=10) as s:
    s.sendall(data)
    s.shutdown(socket.SHUT_WR)  # Señala fin del envío
    respuesta = s.recv(4096)
    

# 6. Mostrar respuesta
print("📥 Respuesta del servidor:")
print(respuesta.decode(errors="replace"))
