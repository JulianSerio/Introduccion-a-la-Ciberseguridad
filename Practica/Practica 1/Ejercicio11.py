from pwn import *
import re
import sys

def xor_bytes(data, key_byte): # Función para aplicar XOR byte a byte
    return bytes(b ^ key_byte for b in data)

# Cadena hexadecimal cifrada
context.log_level = 'debug'

# Conectar al servidor (misma dirección/puerto que pusiste)
con = remote("ic.catedras.linti.unlp.edu.ar", 11015)
# Convertir a bytes
con.readuntil("encripada con 4 caracteres, como pista le damos que la primera palabra es:\n")
hexstr = con.readline();
cipher_bytes = bytes.fromhex(hexstr)

known_plaintext = b'


# Paso 1: encontrar clave XOR
first_cipher = cipher_bytes[:4]
key = bytes([c ^ p for c, p in zip(first_cipher, known_plaintext)])
print("Clave encontrada:", key)

# Paso 2: desencriptar usando la clave
full_key = cycle(key)
plaintext = bytes([c ^ k for c, k in zip(cipher_bytes, full_key)])
print("Texto plano:", plaintext.decode(errors='ignore'))
