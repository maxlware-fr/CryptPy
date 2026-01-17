from PyQt6 import QtWidgets
from PyQt6.QtWidgets import QApplication, QMainWindow, QLabel, QLineEdit, QPushButton, QVBoxLayout, QWidget
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

BS = 16

def pad(s):
    pad_len = BS - len(s) % BS
    return s + chr(pad_len) * pad_len

def unpad(s):
    return s[:-ord(s[-1])]

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

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CryptPy GUI")
        self.setFixedSize(600, 400)

        layout = QVBoxLayout()

        self.input_text = QLineEdit()
        self.input_text.setPlaceholderText("Texte à chiffrer/déchiffrer")

        self.key_text = QLineEdit()
        self.key_text.setPlaceholderText("Clé secrète")

        self.encrypt_btn = QPushButton("Chiffrer")
        self.decrypt_btn = QPushButton("Déchiffrer")

        self.output_label = QLabel("")
        self.output_label.setWordWrap(True)

        layout.addWidget(self.input_text)
        layout.addWidget(self.key_text)
        layout.addWidget(self.encrypt_btn)
        layout.addWidget(self.decrypt_btn)
        layout.addWidget(self.output_label)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

        self.encrypt_btn.clicked.connect(self.encrypt)
        self.decrypt_btn.clicked.connect(self.decrypt)

    def encrypt(self):
        text = self.input_text.text()
        key = self.key_text.text()
        if not text or not key:
            self.output_label.setText("Veuillez entrer le texte et la clé.")
            return
        result = aes_encrypt(text, key)
        self.output_label.setText(f"Chiffré :\n{result}")

    def decrypt(self):
        text = self.input_text.text()
        key = self.key_text.text()
        if not text or not key:
            self.output_label.setText("Veuillez entrer le texte et la clé.")
            return
        try:
            result = aes_decrypt(text, key)
            self.output_label.setText(f"Déchiffré :\n{result}")
        except Exception as e:
            self.output_label.setText("Erreur de déchiffrement.")

if __name__ == "__main__":
    app = QApplication([])
    window = MainWindow()
    window.show()
    app.exec()
