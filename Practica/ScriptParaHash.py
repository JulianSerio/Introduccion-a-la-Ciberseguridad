from pwn import *
import hashlib

def shaCheck(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def buscarpswd(passwordObjetivo):
    with open("passwd.txt", "r") as archivo:
        for pswd in archivo:
            if shaCheck(pswd.rstrip('\r\n')) == passwordObjetivo:
                return pswd.rstrip('\r\n')



linea_hash = "881486ba0abc356fa032acd1bf7d37ddb6ea3e34fe271f3133ea2ec1dca4fbb6"
print("----------HASH---------------");
print("Hash:",linea_hash)
print("Tipo:",type(linea_hash))
password = buscarpswd(linea_hash)
print("----------PASSWORD---------------");
print("Password:",password)
print("Tipo:",type(password))

