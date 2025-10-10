#!/usr/bin/env python3
import math

n = 1452449184624535635757449085988204487494222248509493899299759
e = 65537
C = 1280743944712857143060627969938538851911171950125979945026152
p = 1153324775179431312178120797679
q = 1259358348907893108175391571521

phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
m = pow(C, d, n)
print("M = ",m)

# Convertimos a bytes
m_bytes = m.to_bytes((m.bit_length() + 7) // 8, 'big')

# Intentamos decodificar como texto UTF-8
try:
    mensaje = m_bytes.decode('utf-8')
except UnicodeDecodeError:
    mensaje = m_bytes.hex()
# --------------------------
# Mostramos resultados
# --------------------------
print(f"[+] p = {p}")
print(f"[+] q = {q}")
print(f"[+] d = {d}")
print(f"[+] m (int) = {m}")
print(f"[+] Mensaje: {mensaje}")
