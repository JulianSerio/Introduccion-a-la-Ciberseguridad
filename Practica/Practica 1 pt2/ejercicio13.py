#!/usr/bin/env python3
from pwn import *
import re
import sys

def parsearAValores(texto_bytes):
    texto = texto_bytes.decode('utf-8', errors='ignore')
    # acepta p, q, e, c con espacios y mayúsc/minúsc
    pattern = re.compile(r'\b([pqecPQEC])\b\s*=\s*([0-9]+)', re.IGNORECASE)
    values = {}
    for match in pattern.finditer(texto):
        key = match.group(1).lower()
        value = int(match.group(2))
        # mantener 'C' mayúscula para distinguir cifra si quieres; aquí uso minúsculas excepto C
        if key == 'c':
            key = 'C'
        values[key] = value
    return values

context.log_level = 'debug'

# Conectar al servidor (misma dirección/puerto que pusiste)
con = remote("ic.catedras.linti.unlp.edu.ar", 11012)

# leer hasta el prompt inicial
con.readuntil("Bienvenidos! Intente desencriptar el siguiente texto:\n")
texto_completo = b""
for _ in range(4): # leer 4 líneas
    linea = con.readline() # incluye \n
    if not linea: 
        break 
    texto_completo += linea #contateno el texto
    if b'c=' in linea.lower(): # si veo la linea con 'c=', corto
        break

print("----- BLOQUE RECIBIDO (raw) -----")
print(texto_completo.decode('utf-8'))
print("---------------------------------")

# parsear p, q, e, c
vals = parsearAValores(texto_completo)
required = ['p','q','e','C']  # keys que esperamos
for r in required:
    if r not in vals:
        print(f"Falta {r} en los datos parseados. Encontrado: {list(vals.keys())}")
        sys.exit(1)

p = vals['p']
q = vals['q']
e = vals['e']
c = vals['C']

print(f"p = {p}")
print(f"q = {q}")
print(f"e = {e}")
print(f"c (bits) = {c.bit_length()}")

n = p * q #calculo n
phi = (p - 1) * (q - 1) #calculo phi
d = pow(e, -1, phi) #calculo d
M = pow(c, d, n) #calculo M
print("M = ",M)    
sys.stdout.flush() #asegura que el output se imprima de una
M_bytes = M.to_bytes((M.bit_length() + 7) // 8, byteorder='big') # Convertir M a bytes
M_str = M_bytes.decode('utf-8') # Convertir bytes a 
print("palabra = ", M_str) # Imprimir el mensaje original
sys.stdout.flush()
con.send((M_str + "\n").encode('utf-8'))
respuesta = con.recvall(timeout=2)
print("----- RESPUESTA DEL SERVIDOR -----")
print(respuesta.decode('utf-8', errors='ignore'))
con.close()
