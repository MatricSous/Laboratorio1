import scapy.all as scapy

def extract_ascii_from_icmp(packets):
    ascii_string = ""
    for packet in packets:
        if packet.haslayer(scapy.ICMP):
            icmp_packet = packet[scapy.ICMP]
            if icmp_packet.type == 8:  # ICMP Request
                ascii_char = chr(icmp_packet.load[0])
                ascii_string += ascii_char
    return ascii_string

def caesar_cipher_decrypt(text, shift):
    decrypted_text = ""
    for char in text:
        if char.isalpha():
            shifted = ord(char) - shift
            if char.islower():
                if shifted < ord('a'):
                    shifted += 26
            elif char.isupper():
                if shifted < ord('A'):
                    shifted += 26
            decrypted_text += chr(shifted)
        else:
            decrypted_text += char
    return decrypted_text

def calculate_frequency(text):
    frequencies = {}
    for char in text:
        if char.isalpha():
            if char in frequencies:
                frequencies[char] += 1
            else:
                frequencies[char] = 1
    total_chars = sum(frequencies.values())
    return {char: count / total_chars for char, count in frequencies.items()}

def most_probable_message(encrypted_text):
    frequencies_espanol = {
        'a': 0.1173, 'b': 0.0123, 'c': 0.0468, 'd': 0.0586, 'e': 0.1368, 'f': 0.0069, 'g': 0.0101,
        'h': 0.0070, 'i': 0.0625, 'j': 0.0044, 'k': 0.0002, 'l': 0.0497, 'm': 0.0315, 'n': 0.0671,
        'o': 0.0868, 'p': 0.0251, 'q': 0.0088, 'r': 0.0687, 's': 0.0798, 't': 0.0463, 'u': 0.0393,
        'v': 0.0090, 'w': 0.0001, 'x': 0.0022, 'y': 0.0090, 'z': 0.0052,
    }

    best_shift = None
    best_score = float('-inf')
    decrypted_message = ""
    all_decrypted_messages = []

    for shift in range(1, 26):
        decrypted_text = caesar_cipher_decrypt(encrypted_text, shift)
        freq = calculate_frequency(decrypted_text)
        score = sum(frequencies_espanol[char] * freq.get(char, 0) for char in frequencies_espanol)
        
        all_decrypted_messages.append((decrypted_text, shift))
        
        if score > best_score:
            best_score = score
            best_shift = shift
            decrypted_message = decrypted_text

    return all_decrypted_messages, decrypted_message, best_shift

if __name__ == "__main__":
    pcapng_file = input("Ingrese el nombre del archivo pcapng: ")
    packets = scapy.rdpcap(pcapng_file)

    ascii_data = extract_ascii_from_icmp(packets)

    if ascii_data:
        print(f"Texto ASCII extraído: {ascii_data}")
        
        all_decrypted_messages, best_decrypted_message, best_shift = most_probable_message(ascii_data)
        
        print("\nTodos los mensajes posibles:")
        for message, shift in all_decrypted_messages:
            if message == best_decrypted_message:
                print(f"\033[92mDesplazamiento {shift}: {message}\033[0m (Más probable)")
            else:
                print(f"Desplazamiento {shift}: {message}")
    else:
        print("No se encontraron paquetes ICMP Request en el archivo.")
