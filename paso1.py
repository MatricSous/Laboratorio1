def cifrar_cesar(texto, clave):
    texto_cifrado = ""
    for caracter in texto:
        if caracter.isalpha():
            mayuscula = caracter.isupper()
            caracter = caracter.lower()
            codigo = ord(caracter)
            codigo_cifrado = ((codigo - ord('a') + clave) % 26) + ord('a')
            if mayuscula:
                caracter_cifrado = chr(codigo_cifrado).upper()
            else:
                caracter_cifrado = chr(codigo_cifrado)
        else:
            caracter_cifrado = caracter
        texto_cifrado += caracter_cifrado
    return texto_cifrado

def main():
    texto = input("Ingrese el texto a cifrar: ")
    clave = int(input("Ingrese la clave de cifrado (un número entero): "))
    
    texto_cifrado = cifrar_cesar(texto, clave)
    
    print("Texto cifrado:", texto_cifrado)

if __name__ == "__main__":
    main()
