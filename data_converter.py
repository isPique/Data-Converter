import binascii
import base64
import base58
import string
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from colorama import Fore, Style, init

init(autoreset = True)

# ------------------------------------------ Data Conversion Algorithms ------------------------------------------ #

def binary_to_ascii(binary_str):
    try:
        binary_values = binary_str.replace(" ", "")
        ascii_result = binascii.unhexlify('%x' % int(binary_values, 2))
        return ascii_result.decode('utf-8')

    except binascii.Error:
        return "Error converting binary to ASCII. Invalid binary value."

    except UnicodeDecodeError as e:
        return f"Error decoding binary bytes to ASCII: {str(e)}"

    except Exception as e:
        return f"Error converting ASCII to binary: {str(e)}"

def ascii_to_binary(ascii_str):
    try:
        ascii_bytes = ascii_str.encode('utf-8')
        binary_result = bin(int(binascii.hexlify(ascii_bytes), 16))[2:]
        return ' '.join([binary_result[i:i + 8] for i in range(0, len(binary_result), 8)])

    except UnicodeEncodeError as e:
        return f"Error encoding ASCII to binary: {str(e)}"

    except Exception as e:
        return f"Error converting ASCII to binary: {str(e)}"

def hexadecimal_to_ascii(hex_str):
    try:
        ascii_result = ''.join(chr(int(hex_str[i:i + 2], 16)) for i in range(0, len(hex_str), 2))
        return ascii_result

    except ValueError:
        return "Error converting hexadecimal to ASCII. Invalid hexadecimal value."

def ascii_to_hexadecimal(ascii_str):
    try:
        hex_result = ''.join(format(ord(char), '02X') for char in ascii_str)
        return hex_result

    except Exception as e:
        return f"Error converting ASCII to hexadecimal: {str(e)}"

def ascii_to_base64(ascii_str):
    try:
        base64_result = base64.b64encode(ascii_str.encode()).decode()
        return base64_result

    except binascii.Error as e:
        return f"Error encoding ASCII to base64: {str(e)}"

    except Exception as e:
        return f"Unexpected error during ASCII to base64 conversion: {str(e)}"

def base64_to_ascii(base64_str):
    try:
        ascii_result = base64.b64decode(base64_str).decode()
        return ascii_result

    except (binascii.Error, UnicodeDecodeError) as e:
        return f"Error decoding base64 to ASCII: {str(e)}"

    except Exception as e:
        return f"Unexpected error during base64 to ASCII conversion: {str(e)}"

# ------------------------------------------ Encoding and Decoding Algorithms ------------------------------------------ #

def ascii_to_rot13(ascii_str):
    try:
        rot13_result = ''.join(
            chr((ord(char) - ord('A') + 13) % 26 + ord('A'))
            if 'A' <= char <= 'Z'
            else chr((ord(char) - ord('a') + 13) % 26 + ord('a'))
            if 'a' <= char <= 'z'
            else char
            for char in ascii_str
        )
        return rot13_result

    except Exception as e:
        return f"Error converting ASCII to ROT13: {str(e)}"

def rot13_to_ascii(rot13_str):
    try:
        ascii_result = ''.join(
            chr((ord(char) - ord('A') - 13) % 26 + ord('A'))
            if 'A' <= char <= 'Z'
            else chr((ord(char) - ord('a') - 13) % 26 + ord('a'))
            if 'a' <= char <= 'z'
            else char
            for char in rot13_str
        )
        return ascii_result

    except Exception as e:
        return f"Error converting ROT13 to ASCII: {str(e)}"

def ascii_to_offset(ascii_str, offset):
    try:
        offset_result = ''.join(
            chr((ord(char) - ord('A') + offset) % 26 + ord('A'))
            if 'A' <= char <= 'Z'
            else chr((ord(char) - ord('a') + offset) % 26 + ord('a'))
            if 'a' <= char <= 'z'
            else char
            for char in ascii_str
        )
        return offset_result

    except Exception as e:
        return f"Error converting ASCII to Offset: {str(e)}"

def offset_to_ascii(offset_str, offset):
    try:
        ascii_result = ''.join(
            chr((ord(char) - ord('A') - offset) % 26 + ord('A'))
            if 'A' <= char <= 'Z'
            else chr((ord(char) - ord('a') - offset) % 26 + ord('a'))
            if 'a' <= char <= 'z'
            else char
            for char in offset_str
        )
        return ascii_result

    except Exception as e:
        return f"Error converting Offset to ASCII: {str(e)}"

# ------------------------------------------ Cryptographic Encryption and Decryption Algorithms ------------------------------------------ #

def ascii_to_base58(ascii_str):
    try:
        base58_result = base58.b58encode(ascii_str.encode()).decode()
        return base58_result

    except binascii.Error as e:
        return f"Error encoding ASCII to base58: {str(e)}"

    except Exception as e:
        return f"Unexpected error during ASCII to base58 conversion: {str(e)}"

def base58_to_ascii(base58_str):
    try:
        ascii_result = base58.b58decode(base58_str).decode()
        return ascii_result

    except (binascii.Error, UnicodeDecodeError) as e:
        return f"Error decoding base58 to ASCII: {str(e)}"

    except Exception as e:
        return f"Unexpected error during base58 to ASCII conversion: {str(e)}"

def ascii_to_rsa(message, public_key):
    try:
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise ValueError("Invalid public key provided for RSA encryption.")

        ciphertext = public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf = padding.MGF1(algorithm = hashes.SHA256()),
                algorithm = hashes.SHA256(),
                label = None,
            )
        )
        return base64.b64encode(ciphertext).decode()

    except ValueError as ve:
        return f"ValueError: {str(ve)}"

    except Exception as e:
        return f"Error during ASCII to RSA encryption: {str(e)}"

def rsa_to_ascii(ciphertext, private_key):
    try:
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise ValueError("Invalid private key provided for RSA decryption.")

        decrypted_message = private_key.decrypt(
            base64.b64decode(ciphertext),
            padding.OAEP(
                mgf = padding.MGF1(algorithm = hashes.SHA256()),
                algorithm = hashes.SHA256(),
                label = None,
            )
        )
        return decrypted_message.decode()

    except ValueError as ve:
        return f"ValueError: {str(ve)}"

    except Exception as e:
        return f"Error during RSA to ASCII decryption: {str(e)}"

def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent = 65537,
        key_size = 2048,
        backend = default_backend()
    )
    public_key = private_key.public_key()

    return private_key, public_key

def ascii_to_aes(message, key, iv):
    try:
        if not isinstance(key, bytes) or not isinstance(iv, bytes):
            raise ValueError("Invalid key or IV provided for AES encryption.")

        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend = default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
        return base64.b64encode(ciphertext).decode()

    except ValueError as ve:
        return f"ValueError: {str(ve)}"

    except Exception as e:
        return f"Error during ASCII to AES encryption: {str(e)}"

def aes_to_ascii(ciphertext, key, iv):
    try:
        if not isinstance(key, bytes) or not isinstance(iv, bytes):
            raise ValueError("Invalid key or IV provided for AES decryption.")

        decryptor = Cipher(algorithms.AES(key), modes.CFB(iv), backend = default_backend()).decryptor()
        decrypted_message = decryptor.update(base64.b64decode(ciphertext)) + decryptor.finalize()
        return decrypted_message.decode()

    except ValueError as ve:
        return f"ValueError: {str(ve)}"

    except Exception as e:
        return f"Error during AES to ASCII decryption: {str(e)}"

def ascii_to_3des(message, key, iv):
    try:
        if not isinstance(key, bytes) or not isinstance(iv, bytes):
            raise ValueError("Invalid key or IV provided for Triple DES encryption.")

        cipher = Cipher(algorithms.TripleDES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
        return base64.b64encode(ciphertext).decode()

    except ValueError as ve:
        return f"ValueError: {str(ve)}"

    except Exception as e:
        return f"Error during ASCII to Triple DES encryption: {str(e)}"

def des3_to_ascii(ciphertext, key, iv):
    try:
        if not isinstance(key, bytes) or not isinstance(iv, bytes):
            raise ValueError("Invalid key or IV provided for Triple DES decryption.")

        decryptor = Cipher(algorithms.TripleDES(key), modes.CFB(iv), backend=default_backend()).decryptor()
        decrypted_message = decryptor.update(base64.b64decode(ciphertext)) + decryptor.finalize()
        return decrypted_message.decode()

    except ValueError as ve:
        return f"ValueError: {str(ve)}"

    except Exception as e:
        return f"Error during Triple DES to ASCII decryption: {str(e)}"

# ------------------------------------------ Main Functions ------------------------------------------ #

def clear_screen():
    os.system('cls||clear') # Execute a system command to clear the screen (works on both Windows and Unix-like systems)

def display_menu():
    clear_screen()

    menu = (
        Fore.LIGHTBLACK_EX + "Choose an option:\n" +
        Fore.RED + "   0. Exit\n" +
        Fore.CYAN + "   1. Binary to ASCII\n" +
        Fore.LIGHTMAGENTA_EX + "   2. ASCII to Binary\n" +
        Fore.LIGHTYELLOW_EX + "   3. Hexadecimal to ASCII\n" +
        Fore.YELLOW + "   4. ASCII to Hexadecimal\n" +
        Fore.GREEN + "   5. Base64 to ASCII\n" +
        Fore.LIGHTRED_EX + "   6. ASCII to Base64\n" +
        Fore.CYAN + "   7. Base58 to ASCII\n" +
        Fore.LIGHTMAGENTA_EX + "   8. ASCII to Base58\n" +
        Fore.LIGHTYELLOW_EX + "   9. ROT13 to ASCII\n" +
        Fore.YELLOW + "  10. ASCII to ROT13\n" +
        Fore.GREEN + "  11. Offset to ASCII\n" +
        Fore.LIGHTRED_EX + "  12. ASCII to Offset\n" +
        Fore.CYAN + "  13. RSA to ASCII\n" +
        Fore.LIGHTMAGENTA_EX + "  14. ASCII to RSA\n" +
        Fore.LIGHTYELLOW_EX + "  15. AES to ASCII\n" +
        Fore.YELLOW + "  16. ASCII to AES\n" +
        Fore.GREEN + "  17. Triple DES to ASCII\n" +
        Fore.LIGHTRED_EX + "  18. ASCII to Triple DES\n" + Style.RESET_ALL
    )

    print(menu)

def display_information():
    clear_screen()

    information = (
        Fore.LIGHTBLACK_EX + "Algorithm Information:\n" +
        Fore.RED + "   0. Exit: Exits the program.\n" +
        Fore.CYAN + "   1. Binary to ASCII: Converts binary strings to ASCII.\n" +
        Fore.LIGHTMAGENTA_EX + "   2. ASCII to Binary: Converts ASCII strings to binary.\n" +
        Fore.LIGHTYELLOW_EX + "   3. Hexadecimal to ASCII: Converts hexadecimal strings to ASCII.\n" +
        Fore.YELLOW + "   4. ASCII to Hexadecimal: Converts ASCII strings to hexadecimal.\n" +
        Fore.GREEN + "   5. Base64 to ASCII: Converts Base64 strings to ASCII.\n" +
        Fore.LIGHTRED_EX + "   6. ASCII to Base64: Converts ASCII strings to Base64.\n" +
        Fore.CYAN + "   7. Base58 to ASCII: Converts Base58 strings to ASCII.\n" +
        Fore.LIGHTMAGENTA_EX + "   8. ASCII to Base58: Converts ASCII strings to Base58.\n" +
        Fore.LIGHTYELLOW_EX + "   9. ROT13 to ASCII: Applies ROT13 transformation to ASCII strings.\n" +
        Fore.YELLOW + "  10. ASCII to ROT13: Reverses ROT13 transformation on ASCII strings.\n" +
        Fore.GREEN + "  11. Offset to ASCII: Decodes ASCII strings with a specified offset.\n" +
        Fore.LIGHTRED_EX + "  12. ASCII to Offset: Encodes ASCII strings with a specified offset.\n" +
        Fore.CYAN + "  13. RSA to ASCII: Decrypts RSA-encrypted strings to ASCII.\n" +
        Fore.LIGHTMAGENTA_EX + "  14. ASCII to RSA: Encrypts ASCII strings using RSA.\n" +
        Fore.LIGHTYELLOW_EX + "  15. AES to ASCII: Decrypts AES-encrypted strings to ASCII.\n" +
        Fore.YELLOW + "  16. ASCII to AES: Encrypts ASCII strings using AES.\n" +
        Fore.GREEN + "  17. Triple DES to ASCII: Decrypts Triple DES-encrypted strings to ASCII.\n" +
        Fore.LIGHTRED_EX + "  18. ASCII to Triple DES: Encrypts ASCII strings using Triple DES.\n" + Style.RESET_ALL
    )

    print(information)
    input(Fore.LIGHTBLACK_EX + "Press Enter to continue...")

rsa_private_key, rsa_public_key = generate_rsa_key_pair()
aes_key = os.urandom(32)
aes_iv = os.urandom(16)
des_key = os.urandom(24)
des_iv = os.urandom(8)

def main():
    while True:
        display_menu()
        choice = input(Fore.LIGHTBLACK_EX + "Enter your choice: " + Fore.LIGHTWHITE_EX)

        if choice == '':
            display_information()
            continue

        if choice not in ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18']:
            print(Fore.RED + "Invalid choice. Please select a valid option (0-18) or press Enter for information." + Style.RESET_ALL)
            input(Fore.LIGHTBLACK_EX + "Press Enter to continue...")
            continue

        elif choice == '0':
            print(Fore.YELLOW + "Exiting the program. Goodbye!" + Style.RESET_ALL)
            break

        elif choice == '1':
            clear_screen()
            binary_input = input(Fore.CYAN + "Enter a binary string: " + Fore.YELLOW)

            if all(char in '01 ' for char in binary_input):
                ascii_result = binary_to_ascii(binary_input)
                if isinstance(ascii_result, str):
                    print(Fore.LIGHTBLUE_EX + "ASCII String: " + Fore.YELLOW + ascii_result + '\n')

                else:
                    print(Fore.RED + ascii_result + Style.RESET_ALL)
                input(Fore.LIGHTBLACK_EX + "Press Enter to continue...")

            else:
                print(Fore.RED + "Invalid binary input. Please enter a valid binary string." + Style.RESET_ALL)
                input(Fore.LIGHTBLACK_EX + "Press Enter to continue...")

        elif choice == '2':
            clear_screen()
            ascii_input = input(Fore.LIGHTMAGENTA_EX + "Enter an ASCII string: " + Fore.YELLOW)

            if all(32 <= ord(char) <= 127 for char in ascii_input):
                binary_result = ascii_to_binary(ascii_input)
                print(Fore.LIGHTBLUE_EX + "Binary String: " + Fore.YELLOW + binary_result + '\n')
                input(Fore.LIGHTBLACK_EX + "Press Enter to continue...")

            else:
                print(Fore.RED + "Invalid ASCII input. Please enter a valid ASCII string." + Style.RESET_ALL)
                input(Fore.LIGHTBLACK_EX + "Press Enter to continue...")

        elif choice == '3':
            clear_screen()
            hex_input = input(Fore.LIGHTYELLOW_EX + "Enter a hexadecimal string: " + Fore.YELLOW)

            if all(char in string.hexdigits for char in hex_input):
                ascii_result = hexadecimal_to_ascii(hex_input)
                print(Fore.LIGHTBLUE_EX + "ASCII String: " + Fore.YELLOW + ascii_result + '\n')
                input(Fore.LIGHTBLACK_EX + "Press Enter to continue...")

            else:
                print(Fore.RED + "Invalid hexadecimal input. Please enter a valid hexadecimal string." + Style.RESET_ALL)
                input(Fore.LIGHTBLACK_EX + "Press Enter to continue...")

        elif choice == '4':
            clear_screen()
            ascii_input = input(Fore.YELLOW + "Enter an ASCII string: " + Fore.YELLOW)

            if all(32 <= ord(char) <= 127 for char in ascii_input):
                hex_result = ascii_to_hexadecimal(ascii_input)
                print(Fore.LIGHTBLUE_EX + "Hexadecimal String: " + Fore.YELLOW + hex_result + '\n')
                input(Fore.LIGHTBLACK_EX + "Press Enter to continue...")

            else:
                print(Fore.RED + "Invalid ASCII input. Please enter a valid ASCII string." + Style.RESET_ALL)
                input(Fore.LIGHTBLACK_EX + "Press Enter to continue...")

        elif choice == '5':
            clear_screen()
            base64_input = input(Fore.GREEN + "Enter a Base64 string: " + Fore.YELLOW)

            ascii_result = base64_to_ascii(base64_input)
            if not ascii_result.startswith("Error"):
                print(Fore.LIGHTBLUE_EX + "ASCII String: " + Fore.YELLOW + ascii_result + '\n')

            else:
                print(Fore.RED + ascii_result + Style.RESET_ALL)

            input(Fore.LIGHTBLACK_EX + "Press Enter to continue...")

        elif choice == '6':
            clear_screen()
            ascii_input = input(Fore.LIGHTRED_EX + "Enter an ASCII string: " + Fore.YELLOW)

            if all(32 <= ord(char) <= 127 for char in ascii_input):
                base64_result = ascii_to_base64(ascii_input)
                if not base64_result.startswith("Error"):
                    print(Fore.LIGHTBLUE_EX + "Base64 String: " + Fore.YELLOW + base64_result + '\n')

                else:
                    print(Fore.RED + base64_result + Style.RESET_ALL)

                input(Fore.LIGHTBLACK_EX + "Press Enter to continue...")

            else:
                print(Fore.RED + "Invalid ASCII input. Please enter a valid ASCII string." + Style.RESET_ALL)
                input(Fore.LIGHTBLACK_EX + "Press Enter to continue...")

        elif choice == '7':
            clear_screen()
            base58_input = input(Fore.CYAN + "Enter a Base58 string: " + Fore.YELLOW)

            ascii_result = base58_to_ascii(base58_input)
            if not ascii_result.startswith("Error"):
                print(Fore.LIGHTBLUE_EX + "ASCII String: " + Fore.YELLOW + ascii_result + '\n')

            else:
                print(Fore.RED + ascii_result + Style.RESET_ALL)

            input(Fore.LIGHTBLACK_EX + "Press Enter to continue...")

        elif choice == '8':
            clear_screen()
            ascii_input = input(Fore.LIGHTMAGENTA_EX + "Enter an ASCII string: " + Fore.YELLOW)

            if all(32 <= ord(char) <= 127 for char in ascii_input):
                base58_result = ascii_to_base58(ascii_input)
                if not base58_result.startswith("Error"):
                    print(Fore.LIGHTBLUE_EX + "Base58 String: " + Fore.YELLOW + base58_result + '\n')

                else:
                    print(Fore.RED + base58_result + Style.RESET_ALL)

                input(Fore.LIGHTBLACK_EX + "Press Enter to continue...")

            else:
                print(Fore.RED + "Invalid ASCII input. Please enter a valid ASCII string." + Style.RESET_ALL)
                input(Fore.LIGHTBLACK_EX + "Press Enter to continue...")

        elif choice == '9':
            clear_screen()
            rot13_input = input(Fore.LIGHTYELLOW_EX + "Enter a ROT13 string: " + Fore.YELLOW)

            if all(32 <= ord(char) <= 127 for char in rot13_input):
                ascii_result = rot13_to_ascii(rot13_input)
                print(Fore.LIGHTBLUE_EX + "ASCII String: " + Fore.YELLOW + ascii_result + '\n')
                input(Fore.LIGHTBLACK_EX + "Press Enter to continue...")

            else:
                print(Fore.RED + "Invalid ROT13 input. Please enter a valid ROT13 string." + Style.RESET_ALL)
                input(Fore.LIGHTBLACK_EX + "Press Enter to continue...")

        elif choice == '10':
            clear_screen()
            ascii_input = input(Fore.YELLOW + "Enter an ASCII string: " + Fore.YELLOW)

            if all(32 <= ord(char) <= 127 for char in ascii_input):
                rot13_result = ascii_to_rot13(ascii_input)
                print(Fore.LIGHTBLUE_EX + "ROT13 String: " + Fore.YELLOW + rot13_result + '\n')
                input(Fore.LIGHTBLACK_EX + "Press Enter to continue...")

            else:
                print(Fore.RED + "Invalid ASCII input. Please enter a valid ASCII string." + Style.RESET_ALL)
                input(Fore.LIGHTBLACK_EX + "Press Enter to continue...")

        elif choice == '11':
            clear_screen()
            offset_input = input(Fore.GREEN + "Enter an offset-encoded string: " + Fore.YELLOW)

            if all(32 <= ord(char) <= 127 for char in offset_input):
                try:
                    offset = int(input(Fore.BLUE + "Enter the offset value used for encoding (integer): " + Fore.YELLOW))
                    ascii_result = offset_to_ascii(offset_input, offset)
                    print(Fore.LIGHTBLUE_EX + f"Decoded ASCII String: " + Fore.YELLOW + ascii_result + '\n')
                    input(Fore.LIGHTBLACK_EX + "Press Enter to continue...")

                except ValueError:
                    print(Fore.RED + "Invalid offset value. Please enter a valid integer." + Style.RESET_ALL)
                    input(Fore.LIGHTBLACK_EX + "Press Enter to continue...")

            else:
                print(Fore.RED + "Invalid offset-encoded input. Please enter a valid encoded string." + Style.RESET_ALL)
                input(Fore.LIGHTBLACK_EX + "Press Enter to continue...")

        elif choice == '12':
            clear_screen()
            ascii_input = input(Fore.LIGHTRED_EX + "Enter an ASCII string: " + Fore.YELLOW)

            if all(32 <= ord(char) <= 127 for char in ascii_input):
                try:
                    offset = int(input(Fore.GREEN + "Enter an offset value (integer): " + Fore.YELLOW))
                    offset_result = ascii_to_offset(ascii_input, offset)
                    print(Fore.LIGHTBLUE_EX + f"Offset {offset} String: " + Fore.YELLOW + offset_result + '\n')
                    input(Fore.LIGHTBLACK_EX + "Press Enter to continue...")

                except ValueError:
                    print(Fore.RED + "Invalid offset value. Please enter a valid integer." + Style.RESET_ALL)
                    input(Fore.LIGHTBLACK_EX + "Press Enter to continue...")

            else:
                print(Fore.RED + "Invalid ASCII input. Please enter a valid ASCII string." + Style.RESET_ALL)
                input(Fore.LIGHTBLACK_EX + "Press Enter to continue...")

        elif choice == '13':
            clear_screen()
            rsa_to_ascii_encrypted_message = input(Fore.CYAN + "Enter an RSA encrypted string: " + Fore.YELLOW)
            rsa_to_ascii_decrypted = rsa_to_ascii(rsa_to_ascii_encrypted_message, rsa_private_key)

            if not rsa_to_ascii_decrypted.startswith("Error"):
                print(Fore.LIGHTBLUE_EX + "RSA Decrypted String: " + Fore.YELLOW + rsa_to_ascii_decrypted + '\n')

            else:
                print(Fore.RED + rsa_to_ascii_decrypted + Style.RESET_ALL)

            input(Fore.LIGHTBLACK_EX + "Press Enter to continue...")

        elif choice == '14':
            clear_screen()
            ascii_to_rsa_message = input(Fore.LIGHTMAGENTA_EX + "Enter an ASCII string: " + Fore.YELLOW)
            ascii_to_rsa_encrypted = ascii_to_rsa(ascii_to_rsa_message, rsa_public_key)

            if not ascii_to_rsa_encrypted.startswith("Error"):
                print(Fore.LIGHTBLUE_EX + "RSA Encrypted String: " + Fore.YELLOW + ascii_to_rsa_encrypted + '\n')

            else:
                print(Fore.RED + ascii_to_rsa_encrypted + Style.RESET_ALL)

            input(Fore.LIGHTBLACK_EX + "Press Enter to continue...")

        elif choice == '15':
            clear_screen()
            aes_to_ascii_encrypted_message = input(Fore.LIGHTYELLOW_EX + "Enter an AES encrypted string: " + Fore.YELLOW)
            aes_to_ascii_decrypted = aes_to_ascii(aes_to_ascii_encrypted_message, aes_key, aes_iv)

            if not aes_to_ascii_decrypted.startswith("Error"):
                print(Fore.LIGHTBLUE_EX + "AES Decrypted String: " + Fore.YELLOW + aes_to_ascii_decrypted + '\n')

            else:
                print(Fore.RED + aes_to_ascii_decrypted + Style.RESET_ALL)

            input(Fore.LIGHTBLACK_EX + "Press Enter to continue...")

        elif choice == '16':
            clear_screen()
            ascii_to_aes_message = input(Fore.YELLOW + "Enter an ASCII string: " + Fore.YELLOW)
            ascii_to_aes_encrypted = ascii_to_aes(ascii_to_aes_message, aes_key, aes_iv)

            if not ascii_to_aes_encrypted.startswith("Error"):
                print(Fore.LIGHTBLUE_EX + "AES Encrypted String: " + Fore.YELLOW + ascii_to_aes_encrypted + '\n')

            else:
                print(Fore.RED + ascii_to_aes_encrypted + Style.RESET_ALL)

            input(Fore.LIGHTBLACK_EX + "Press Enter to continue...")

        elif choice == '17':
            clear_screen()
            des3_to_ascii_encrypted_message = input(Fore.GREEN + "Enter a Triple DES encrypted string: " + Fore.YELLOW)
            des3_to_ascii_decrypted = des3_to_ascii(des3_to_ascii_encrypted_message, des_key, des_iv)

            if not des3_to_ascii_decrypted.startswith("Error"):
                print(Fore.LIGHTBLUE_EX + "Triple DES Decrypted String: " + Fore.YELLOW + des3_to_ascii_decrypted + '\n')

            else:
                print(Fore.RED + des3_to_ascii_decrypted + Style.RESET_ALL)

            input(Fore.LIGHTBLACK_EX + "Press Enter to continue...")

        elif choice == '18':
            clear_screen()
            ascii_to_3des_message = input(Fore.LIGHTRED_EX + "Enter an ASCII string: " + Fore.YELLOW)
            ascii_to_3des_encrypted = ascii_to_3des(ascii_to_3des_message, des_key, des_iv)

            if not ascii_to_3des_encrypted.startswith("Error"):
                print(Fore.LIGHTBLUE_EX + "Triple DES Encrypted String: " + Fore.YELLOW + ascii_to_3des_encrypted + '\n')

            else:
                print(Fore.RED + ascii_to_3des_encrypted + Style.RESET_ALL)

            input(Fore.LIGHTBLACK_EX + "Press Enter to continue...")

if __name__ == "__main__":
    try:
        main() # Start the main program loop

    except KeyboardInterrupt:
        print(Fore.YELLOW + "\nwhy didn't you use option 0 :(" + Style.RESET_ALL)