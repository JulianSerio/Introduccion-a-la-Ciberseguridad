from pwn import *
import hashlib

def shaCheck(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def buscarpswd(passwordObjetivo):
    with open("passwd.txt", "r") as archivo:
        for pswd in archivo:
            if shaCheck(pswd.rstrip('\r\n')) == passwordObjetivo:
                return pswd.rstrip('\r\n')

context.log_level = 'debug'
con = remote("ic.catedras.linti.unlp.edu.ar", 11007)
con.readuntil("Bienvenidos! Tienen un segundo para averiguar a que password pertenece este hash SHA-256 (pista: Se encuentra entre las primeras 100 del diccionario rockyou.txt):\n")
linea_bytes = con.readline().rstrip(b"\r\n")
print("----------CONTENIDO---------------");
print("Contenido:",linea_bytes)
print("Tipo:",type(linea_bytes))
linea_hash = linea_bytes.decode('utf-8')
print("----------HASH---------------");
print("Hash:",linea_hash)
print("Tipo:",type(linea_hash))
password = buscarpswd(linea_hash)
print("----------PASSWORD---------------");
print("Password:",password)
print("Tipo:",type(password))

con.send((password + "\n").encode('utf-8'))
respuesta = con.readall()
print(respuesta.decode('utf-8'))