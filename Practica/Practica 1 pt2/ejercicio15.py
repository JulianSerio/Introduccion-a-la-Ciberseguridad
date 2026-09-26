from pwn import remote, context
import re
import random
import math

def parse_int_from_line(s: str):
    """Extrae el primer entero decimal o hex (0x...) de la línea y lo devuelve como int."""
    s = s.strip()
    # buscar 0x.. o dígitos
    m = re.search(r"(0x[0-9a-fA-F]+|\d+)", s)
    if not m:
        raise ValueError(f"No integer found in line: {s!r}")
    token = m.group(1)
    return int(token, 0)  # base 0 acepta hex 0x y decimal


def trial_factor(n):
    from math import isqrt
    for i in range(2, isqrt(n) + 1):
        if n % i == 0:
            return i, n // i
    return None, None  

def pollard_rho_simple(n):
    if n % 2 == 0:
        return 2
    x = random.randint(2, n-1)
    y = x
    c = random.randint(1, n-1)
    d = 1

    f = lambda x: (x*x + c) % n

    while d == 1:
        x = f(x)
        y = f(f(y))
        d = math.gcd(abs(x - y), n)
    if d == n:
        return None  # fallo al encontrar divisor
    return d

context.log_level = 'debug'
con = remote("ic.catedras.linti.unlp.edu.ar", 11017)

# Leer hasta la pista (ajusta si cambia el prompt)
con.recvuntil(b"Bienvenidos! Intente desencriptar el siguiente texto:\n")
# El recvline() toma bytes, el decode lo pasa a string
# Recibir líneas completas
n_line = con.recvline().decode(errors='ignore').strip()
e_line = con.recvline().decode(errors='ignore').strip()
C_line = con.recvline().decode(errors='ignore').strip()

print("[+] Línea n:", n_line)
print("[+] Línea e:", e_line)
print("[+] Línea C:", C_line)

# Parsear valores enteros
n = parse_int_from_line(n_line)
e = parse_int_from_line(e_line)
C = parse_int_from_line(C_line)

print("[+] Línea n:", n)
print("[+] Línea e:", e)
print("[+] Línea C:", C)


# Intentar factorizar con Pollard Rho
factor = pollard_rho_simple(n)
if factor:
    p = factor
    q = n // factor
    print(f"[+] Factor encontrado con Pollard Rho: p={p}, q={q}")
else:
    # Intentar factorizar con trial simple
    p, q = trial_factor(n)
    if p is None:
        print("No se pudo factorizar n con ninguno de los métodos.")
        exit(1)
    else:
        print(f"[+] Factor encontrado con trial simple: p={p}, q={q}")

# Calcular clave privada y desencriptar
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
m = pow(C, d, n)

print(f"[+] d = {d}")
print(f"[+] m (int) = {m}")

try:
    # Convertimos el numero entero a bytes
    m_bytes = m.to_bytes((m.bit_length() + 7) // 8, 'big')
    # Lo decodifico
    mensaje = m_bytes.decode('utf-8')
    print("[+] Mensaje decodificado:", mensaje)
    con.sendline(mensaje.encode('utf-8'))
    con.recvuntil(b"Respuesta:")
    print("Respuesta:", con.recvall(timeout=2).decode(errors='ignore'))
    con.close()
except Exception as ex:
    print("[!] No se pudo decodificar mensaje:", ex)




