from pwn import *
import hashlib

def md5Hash(texto):
    return hashlib.md5(texto.encode('utf-8')).hexdigest()

context.log_level = 'debug'
# Nos conectamos utilizando remote
con = remote("ic.catedras.linti.unlp.edu.ar", 11006)
# leemos hasta justo antes de Hash, es decir, hasta ":\n"
con.readuntil("de la siguiente palabra:\n")
# Leemos hasta el salto de línea
linea_bytes = con.readline().rstrip(b"\r\n")
print("----------CONTENIDO---------------");
print("Contenido:",linea_bytes)
print("Tipo:",type(linea_bytes))
print("----------CONTENIDO EN HASH MD5---------------");
linea_hash = md5Hash(linea_bytes.decode('utf-8'))
print("Contenido:",linea_hash)
print("Tipo:",type(linea_hash))
print("");
con.send((linea_hash + "\n").encode('utf-8'))

# Leer e imprimir toda la respuesta del servidor
respuesta = con.readall()
print(respuesta.decode('utf-8'))