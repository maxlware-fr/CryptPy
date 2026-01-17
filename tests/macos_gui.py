from PyQt6 import QtWidgets, QtCore
from PyQt6.QtWidgets import QApplication, QMainWindow, QLabel, QLineEdit, QPushButton, QVBoxLayout, QWidget, QHBoxLayout, QFrame
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
        self.setWindowTitle("CryptPy")
        self.setFixedSize(700, 450)

        # Window style
        self.setStyleSheet("""
            QWidget {
                background: #F5F5F7;
                color: #1C1C1E;
                font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", "Segoe UI", sans-serif;
            }
            QLineEdit {
                background: #FFFFFF;
                border: 1px solid #D1D1D6;
                border-radius: 12px;
                padding: 10px;
            }
            QPushButton {
                background: #007AFF;
                color: white;
                border: none;
                border-radius: 12px;
                padding: 10px;
                font-weight: 600;
            }
            QPushButton:hover {
                background: #005BBB;
            }
            QPushButton:pressed {
                background: #004C99;
            }
            QLabel#title {
                font-size: 22px;
                font-weight: 700;
            }
            QLabel#subtitle {
                font-size: 14px;
                color: #6E6E73;
            }
            QFrame#line {
                background: #D1D1D6;
                max-height: 1px;
            }
        """)

        layout = QVBoxLayout()

        title = QLabel("CryptPy")
        title.setObjectName("title")
        subtitle = QLabel("Multi-layer encryption tool (AES + …)")
        subtitle.setObjectName("subtitle")

        layout.addWidget(title)
        layout.addWidget(subtitle)

        line = QFrame()
        line.setObjectName("line")
        line.setFrameShape(QFrame.Shape.HLine)
        layout.addWidget(line)

        self.input_text = QLineEdit()
        self.input_text.setPlaceholderText("Texte à chiffrer/déchiffrer")

        self.key_text = QLineEdit()
        self.key_text.setPlaceholderText("Clé secrète")

        btn_layout = QHBoxLayout()
        self.encrypt_btn = QPushButton("Chiffrer")
        self.decrypt_btn = QPushButton("Déchiffrer")
        btn_layout.addWidget(self.encrypt_btn)
        btn_layout.addWidget(self.decrypt_btn)

        self.output_label = QLabel("")
        self.output_label.setWordWrap(True)
        self.output_label.setStyleSheet("padding: 10px; background: #FFFFFF; border: 1px solid #D1D1D6; border-radius: 12px;")

        layout.addWidget(self.input_text)
        layout.addWidget(self.key_text)
        layout.addLayout(btn_layout)
        layout.addWidget(self.output_label)

        container = QWidget()
        container.setLayout(layout)
        container.setContentsMargins(20, 20, 20, 20)
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
        except Exception:
            self.output_label.setText("Erreur de déchiffrement.")


if __name__ == "__main__":
    app = QApplication([])
    window = MainWindow()
    window.show()
    app.exec()
