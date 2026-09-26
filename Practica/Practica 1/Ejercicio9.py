import base64
from Crypto.Cipher import AES

cadena = "dV5t6M4m2AcjYWsxC9iO+YXlc0r0ClfwyTGtpuWdPh9fvH+8cejJWOH" \
"Yq1qH7qA+Kj7Lci133Awj3rnoq42p532+fvbN64oZ8R/TlMkhw47nmIM5gPN+rt4" \
"5985jeiIDbdpCu1ig09Rzepl4/kawM1AzFtoMzTvadmx11qSFp+UD81yiRz6HjaFLII" \
"IIQnbzFrmcOIOGEQ6LBEYz2cTW6JPBs7MHpqDrcrzZoLcb7Ah2jQSIId+YZ90JmRt83yTe66a60kqL5" \
"SoW7/463Suyyp9xDhrgFu6YS3ScNDgOamADIcKmLUTxrvYooZIjL7s+thek3aBPrv/yB84YNUhX7MOxji" \
"TiP02nBJ1E1dOA0ew75BeARB4cHKVfLMnPMkjSYyiQ2eTWqYd4cZ+14Z9joNVA1Uei8Pg4KITPfJYy3Mc="


cadena64 = base64.b64decode(cadena)  # Decodificamos la cadena base64
print("CADENA DESCODIFICADA A Base64:",cadena64)
print("TIPO ",type(cadena64))
objetoAES = AES.new(b'CLAVE RE SECRETA', AES.MODE_ECB)  # Creamos el objeto AES
print("");
print("OBJETO AES:",objetoAES)
print("TIPO ",type(objetoAES))
cadenaAES = objetoAES.decrypt(cadena64)  # Desencriptamos la cadena
print("");
print(cadenaAES.decode('utf-8'))  # Imprimimos la cadena desencript
print("TIPO ",type(cadenaAES))