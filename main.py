import base64
import hashlib
import time
import sys
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

BS = 16

def pad(s):
    pad_len = BS - len(s) % BS
    return s + chr(pad_len) * pad_len

def unpad(s):
    return s[:-ord(s[-1])]

def cesar_encrypt(text, shift=5):
    return ''.join(chr((ord(c) + shift) % 256) for c in text)

def cesar_decrypt(text, shift=5):
    return ''.join(chr((ord(c) - shift) % 256) for c in text)

def vigenere_encrypt(text, key):
    key = (key * (len(text) // len(key) + 1))[:len(text)]
    return ''.join(chr((ord(c) + ord(k)) % 256) for c, k in zip(text, key))

def vigenere_decrypt(text, key):
    key = (key * (len(text) // len(key) + 1))[:len(text)]
    return ''.join(chr((ord(c) - ord(k)) % 256) for c, k in zip(text, key))

def base64_encrypt(text):
    return base64.b64encode(text.encode()).decode()

def base64_decrypt(text):
    return base64.b64decode(text.encode()).decode()

def xor_encrypt(text, key):
    return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(text))

def xor_decrypt(text, key):
    return xor_encrypt(text, key)

def aes_encrypt(text, key):
    key = hashlib.sha256(key.encode()).digest()
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(text).encode())
    return base64.b64encode(iv + encrypted).decode()

def aes_decrypt(encrypted_text, key):
    key = hashlib.sha256(key.encode()).digest()
    raw = base64.b64decode(encrypted_text)
    iv = raw[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(raw[16:]).decode()
    return unpad(decrypted)

def loading(message="Traitement en cours", duration=2):
    sys.stdout.write(message)
    sys.stdout.flush()
    for _ in range(duration * 4):
        time.sleep(0.25)
        sys.stdout.write(".")
        sys.stdout.flush()
    print()

def encrypt_all(text, key):
    loading("Chiffrement")
    step1 = cesar_encrypt(text)
    step2 = vigenere_encrypt(step1, key)
    step3 = base64_encrypt(step2)
    step4 = xor_encrypt(step3, key)
    step5 = aes_encrypt(step4, key)
    return step5

def decrypt_all(text, key):
    loading("Déchiffrement")
    step1 = aes_decrypt(text, key)
    step2 = xor_decrypt(step1, key)
    step3 = base64_decrypt(step2)
    step4 = vigenere_decrypt(step3, key)
    step5 = cesar_decrypt(step4)
    return step5

def separator():
    print("=" * 50)

def main():
    separator()
    print(" CryptPy - Multi-layer encryption tool")
    print(" By Maxlware")
    separator()
    print(" 1 - Encrypter un texte")
    print(" 2 - Décrypter un texte")
    separator()
    choice = input(" Choix (1/2) : ").strip()
    if choice == "1":
        text = input("\n Texte à chiffrer : ").strip()
        key = input(" Clé secrète (au choix) : ").strip()
        result = encrypt_all(text, key)
        separator()
        print(" Texte chiffré :\n")
        print(result)
        separator()

    elif choice == "2":
        text = input("\n Texte à déchiffrer : ").strip()
        key = input(" Clé secrète utilisée : ").strip()
        try:
            result = decrypt_all(text, key)
            separator()
            print(" Texte déchiffré :\n")
            print(result)
            separator()
        except Exception as e:
            print("\n [Erreur] Le déchiffrement a échoué :", e)
    else:
        print(" Choix invalide.")

if __name__ == "__main__":
    main()
