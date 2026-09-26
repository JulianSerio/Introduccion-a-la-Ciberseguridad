from pwn import remote, context
import re
import random


def parse_int_from_line(s: str):
    """Extrae el primer entero decimal o hex (0x...) de la línea y lo devuelve como int."""
    s = s.strip()
    # buscar 0x.. o dígitos
    m = re.search(r"(0x[0-9a-fA-F]+|\d+)", s)
    if not m:
        raise ValueError(f"No integer found in line: {s!r}")
    token = m.group(1)
    return int(token, 0)  # base 0 acepta hex 0x y decimal


context.log_level = 'debug'
con = remote("ic.catedras.linti.unlp.edu.ar", 11018)

# Leer hasta la pista (ajusta si cambia el prompt)
con.recvuntil(b"Diffie Hellman:\n")
# El recvline() toma bytes, el decode lo pasa a string
# Recibir líneas completas
p_line = con.recvline().decode(errors='ignore').strip()
g_line = con.recvline().decode(errors='ignore').strip()
public_alice_line = con.recvline().decode(errors='ignore').strip()
private_bob_line = con.recvline().decode(errors='ignore').strip()

# Función para parsear líneas y extraer enteros
p = parse_int_from_line(p_line)
g = parse_int_from_line(g_line)
public_alice = parse_int_from_line(public_alice_line)
private_bob = parse_int_from_line(private_bob_line)

print("[+] Línea p:", p)
print("[+] Línea g:", g)
print("[+] Línea public Alice:", public_alice)
print("[+] Línea private Bob:", private_bob)

k = pow(public_alice, private_bob, p)  
print(f"[+] k (clave compartida) = {k}")
con.sendline(str(k).encode('utf-8'))
con.recvuntil(b"Respuesta:")
print("Respuesta:", con.recvall(timeout=2).decode(errors='ignore'))
con.close()