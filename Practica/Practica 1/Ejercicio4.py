from pwn import *

def rotX(texto,X):
    resultado = ""
    for c in texto:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            # Desplazar el carácter 23 posiciones
            resultado += chr(base + (ord(c) - base + X) % 26)
        else:
            resultado += c
    return resultado

def obtenerTipoRot():
    con.readuntil("ROT")
    nro = con.readuntil(" de esta frase:\n", drop=True)
    return int(nro)


context.log_level = 'debug'
# Nos conectamos utilizando remote
con = remote("ic.catedras.linti.unlp.edu.ar", 11004)
# leemos hasta justo antes de ROT, es decir, hasta ":\n"
x = obtenerTipoRot()
print("----------ROT---------------");
print("Tipo de ROT:",x)
# Leemos hasta el salto de línea
linea_bytes = con.readline().rstrip(b"\r\n")
print("----------CONTENIDO---------------");
print("Contenido:",linea_bytes)
print("Tipo:",type(linea_bytes))
print("----------CONTENIDO EN ROT---------------");
linea_enrot = rotX(linea_bytes.decode('utf-8'), x)
print("Contenido:",linea_enrot)
print("Tipo:",type(linea_enrot))
print("");
con.send((linea_enrot + "\n").encode('utf-8'))

# Leer e imprimir toda la respuesta del servidor
respuesta = con.readall()
print(respuesta.decode('utf-8'))