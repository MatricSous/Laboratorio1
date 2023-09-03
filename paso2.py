import scapy.all as scapy
import sys

# Función para cifrar el mensaje utilizando el cifrado César
def cifrar_cesar(texto, corrimiento):
    mensaje_cifrado = ""
    for caracter in texto:
        if caracter.isalpha():
            mayuscula = caracter.isupper()
            caracter = caracter.lower()
            ascii_valor = ord(caracter)
            ascii_valor_cifrado = ((ascii_valor - 97 + corrimiento) % 26) + 97
            if mayuscula:
                caracter_cifrado = chr(ascii_valor_cifrado).upper()
            else:
                caracter_cifrado = chr(ascii_valor_cifrado)
        else:
            caracter_cifrado = caracter
        mensaje_cifrado += caracter_cifrado
    return mensaje_cifrado

# Función para crear un paquete ICMP personalizado de 48 bytes
def crear_paquete_icmp(caracter, identificador, secuencia):
    # Rellenar bytes del 10 al 37
    relleno = bytes(range(10, 38))
    
    # Asegurar que el mensaje cifrado tenga 1 byte
    mensaje_cifrado = caracter.encode().ljust(1)

    # Crear un paquete ICMP de 48 bytes con el carácter cifrado en el primer byte de los primeros 8 bytes del campo de datos
    paquete = scapy.IP(dst="8.8.8.8") / scapy.ICMP(id=identificador, seq=secuencia) / (mensaje_cifrado + bytes([0]) * 7 + b'\x10'+ b'\x11'+ b'\x12'+ b'\x13'+ b'\x14' + b'\x15' + b'\x16' + b'\x17' + b'\x18' + b'\x19' + b'\x1a'+ b'\x1b' + b'\x1c' + b'\x1d' + b'\x1e' + b'\x1f'+ b'\x20' + b'\x21' + b'\x22' + b'\x23' + b'\x24' + b'\x25' + b'\x26' + b'\x27' + b'\x28' + b'\x29'+ b'\x2a' + b'\x2b' + b'\x2c' + b'\x2d' + b'\x2e' + b'\x2f'+ b'\x30' + b'\x31' + b'\x32' + b'\x33' + b'\x34' + b'\x35' + b'\x36' + b'\x37')
    
    return paquete

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Uso: python script.py <texto> <corrimiento>")
        sys.exit(1)

    texto = sys.argv[1]
    corrimiento = int(sys.argv[2])
    
    for i, caracter in enumerate(texto):
        mensaje_cifrado = cifrar_cesar(caracter, corrimiento)
        paquete_icmp = crear_paquete_icmp(mensaje_cifrado, 1234, i)
        scapy.send(paquete_icmp)
