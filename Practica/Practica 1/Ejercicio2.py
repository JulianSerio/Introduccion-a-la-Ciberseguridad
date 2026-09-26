from pwn import *
import base64

# Para debug del socket utilizamos:
context.log_level = 'debug'
# Analice las diferencias entre usar o no el debug
# Nos conectamos utilizando remote
con = remote("ic.catedras.linti.unlp.edu.ar", 11002)
# para quitar el texto que no nos interesa (banner),
# leemos hasta justo antes de la cuenta, es decir, hasta ":\n"
con.readuntil("base64 esta palabra:\n")
# Leemos hasta el salto de línea, la palabra a encodear luego elimina los caracteres de fin de linea
linea_bytes = con.readline().rstrip(b"\r\n")

# Convertir los bytes a texto (str)
linea_str = linea_bytes.decode('utf-8')

# Codificar la cadena en Base64 y obtenerla como str
linea_base64 = base64.b64encode(linea_str.encode('utf-8')).decode('utf-8')

# Enviar la línea codificada en base64 al servidor (como bytes)
con.send((linea_base64 + "\n").encode('utf-8'))

# Leer e imprimir toda la respuesta del servidor
respuesta = con.readall()
print(respuesta.decode('utf-8'))