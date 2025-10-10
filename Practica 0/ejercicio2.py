from pwn import *
# Para debug del socket utilizamos:
context.log_level = 'debug'
# Analice las diferencias entre usar o no el debug
# Nos conectamos utilizando remote
con = remote("ic.catedras.linti.unlp.edu.ar", 10002)
# para quitar el texto que no nos interesa (banner),
# leemos hasta justo antes de la cuenta, es decir, hasta ":\n"
con.readuntil("obtener la flag!:\n")
# Leemos hasta el salto de línea, la cuenta deseada
cuenta = con.readline()
print("----PRIMERA OP----")
print(type(cuenta))
print(cuenta)
# Pasamos los bytes a string, para poder realizar la cuenta
cuenta = cuenta.decode()
# Split convierte una cadena de texto en una lista, utilizando como
# espacios en blanco
cuenta = cuenta.split() # ['297', '+', '155']
# Convierto a entero los operandos
op1 = int(cuenta[0])
op2 = int(cuenta[2])
operador = cuenta[1]
print("operacion 1: ", op1)
print("OPERADOR: ", operador)
print("operacion 2: ", op2)

# Sumo multiplico o resto según el operador
if operador == '+':
    resultado = op1 + op2
elif operador == '*':
    resultado = op1 * op2
else:
    resultado = op1 - op2

# Enviamos la respuesta de la cuenta, como bytes:
con.send((str(resultado) + "\n").encode())
# Imprimimos toda la respuesta del servidor

entero = int(1)
for i in range(500):
    con.readuntil("Correcto! A resolver!:\n")
    cuenta = con.readline()  # Leemos la cuenta
    print(f"----OP {entero}----")
    entero = entero + 1
    print(type(cuenta))
    print(cuenta)
    
    # Convertimos los bytes a string
    cuenta = cuenta.decode().strip()
    print(f"Cuenta: {cuenta}")
    
    # Dividimos la cuenta en una lista: ['297', '+', '155']
    cuenta = cuenta.split()
    
    # Convertimos a enteros los operandos
    op1 = int(cuenta[0])
    op2 = int(cuenta[2])
    operador = cuenta[1]
    
    print("Operacion 1: ", op1)
    print("OPERADOR: ", operador)
    print("Operacion 2: ", op2)

    # Resolvemos la operación según el operador
    if operador == '+':
        resultado = op1 + op2
    elif operador == '*':
        resultado = op1 * op2
    else:
        resultado = op1 - op2

    # Enviamos la respuesta al servidor como bytes
    con.send((str(resultado) + "\n").encode())


print(con.readall())