def xor_bytes(data, key_byte): # Función para aplicar XOR byte a byte
    return bytes(b ^ key_byte for b in data)

# Cadena hexadecimal cifrada
cadena_hexa = "08296632232822342f27356637332366252f2034273466252928661e09146a66252e236866162334296624332328296a662a2766202a272166222366233532236634233229662335660f053d092c7619257628193e7634676767737e7f737f73737f192527352f192e27252d232334343b"

# Convertir a bytes
data = bytes.fromhex(cadena_hexa)
longitud_datos = 300

# Probar todas las claves posibles (0 a 255)
for key in range(256):
    resultado = xor_bytes(data, key)
    try: # Bloque Try porque la conversion de bytes a string puede fallar
        texto = resultado.decode('utf-8') # Intentar decodificar a UTF-8
        if all(32 <= ord(c) <= 126 or c in '\n\r\t' for c in texto):  # Filtrar cadenas ilegibles
            print(f"Clave: {key} (0x{key:02x}) → Mensaje: {texto[:longitud_datos]}...")
    except UnicodeDecodeError:
        continue
