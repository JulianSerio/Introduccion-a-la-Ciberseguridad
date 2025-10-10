import sys
p = 1411681044962247700471424630708374925648758544093881877
q = 1025477764739116170232001755962926569489838949121232767
e = 65537
C = 244800329353906336350382253088680972646706962639783844335948234085022348400763256559770095538177770365047075

n = p * q #calculo n
phi = (p - 1) * (q - 1) #calculo phi
d = pow(e, -1, phi) #calculo d
M = pow(C, d, n) #calculo M
print(M)    
sys.stdout.flush() #asegura que el output se imprima de una
M_bytes = M.to_bytes((M.bit_length() + 7) // 8, byteorder='big') # Convertir M a bytes
M_str = M_bytes.decode('utf-8') # Convertir bytes a str
print(M_str) # Imprimir el mensaje original
sys.stdout.flush()
