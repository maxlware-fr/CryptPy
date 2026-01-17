from PyQt6 import QtWidgets, QtCore, QtGui
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QLabel, QLineEdit, QPushButton,
    QVBoxLayout, QWidget, QHBoxLayout, QFrame, QTextEdit
)
import base64, hashlib, time, sys
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

def encrypt_all(text, key):
    step1 = cesar_encrypt(text)
    step2 = vigenere_encrypt(step1, key)
    step3 = base64_encrypt(step2)
    step4 = xor_encrypt(step3, key)
    step5 = aes_encrypt(step4, key)
    return step5

def decrypt_all(text, key):
    step1 = aes_decrypt(text, key)
    step2 = xor_decrypt(step1, key)
    step3 = base64_decrypt(step2)
    step4 = vigenere_decrypt(step3, key)
    step5 = cesar_decrypt(step4)
    return step5


class MacWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CryptPy")
        self.setFixedSize(760, 520)

        # window style macOS-like
        self.setWindowFlag(QtCore.Qt.WindowType.FramelessWindowHint)
        self.setAttribute(QtCore.Qt.WidgetAttribute.WA_TranslucentBackground)

        # main container
        self.container = QWidget()
        self.container.setObjectName("container")
        self.setCentralWidget(self.container)

        self.init_ui()
        self.apply_styles()

        # allow dragging window
        self.old_pos = None

    def init_ui(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(12)

        # top bar (close/minimize)
        top_bar = QHBoxLayout()
        top_bar.setSpacing(10)

        red = self.make_circle("#FF5F57")
        yellow = self.make_circle("#FFBD2E")
        green = self.make_circle("#28C940")

        top_bar.addWidget(red)
        top_bar.addWidget(yellow)
        top_bar.addWidget(green)
        top_bar.addStretch()

        layout.addLayout(top_bar)

        # title
        title = QLabel("CryptPy")
        title.setObjectName("title")

        subtitle = QLabel("Multi-layer encryption • César + Vigenère + Base64 + XOR + AES")
        subtitle.setObjectName("subtitle")

        layout.addWidget(title)
        layout.addWidget(subtitle)

        # separator
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setObjectName("sep")
        layout.addWidget(sep)

        # input
        self.input_text = QTextEdit()
        self.input_text.setPlaceholderText("Texte à chiffrer/déchiffrer…")
        self.input_text.setFixedHeight(120)

        self.key_text = QLineEdit()
        self.key_text.setPlaceholderText("Clé secrète…")

        # buttons
        btn_layout = QHBoxLayout()
        self.encrypt_btn = QPushButton("Chiffrer")
        self.decrypt_btn = QPushButton("Déchiffrer")
        btn_layout.addWidget(self.encrypt_btn)
        btn_layout.addWidget(self.decrypt_btn)

        # output
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setPlaceholderText("Résultat…")
        self.output_text.setFixedHeight(160)

        layout.addWidget(self.input_text)
        layout.addWidget(self.key_text)
        layout.addLayout(btn_layout)
        layout.addWidget(self.output_text)

        self.container.setLayout(layout)

        self.encrypt_btn.clicked.connect(self.encrypt)
        self.decrypt_btn.clicked.connect(self.decrypt)

    def make_circle(self, color):
        w = QLabel()
        w.setFixedSize(14, 14)
        w.setStyleSheet(f"background: {color}; border-radius: 7px;")
        return w

    def apply_styles(self):
        self.container.setStyleSheet("""
            #container {
                background: rgba(245, 245, 247, 0.85);
                border: 1px solid rgba(209, 209, 214, 0.7);
                border-radius: 18px;
            }
            QLabel#title {
                font-size: 24px;
                font-weight: 700;
                color: #1C1C1E;
            }
            QLabel#subtitle {
                font-size: 13px;
                color: #6E6E73;
            }
            QLineEdit, QTextEdit {
                background: rgba(255, 255, 255, 0.75);
                border: 1px solid rgba(209, 209, 214, 0.8);
                border-radius: 14px;
                padding: 10px;
                font-size: 14px;
                color: #1C1C1E;
            }
            QPushButton {
                background: #007AFF;
                color: white;
                border: none;
                border-radius: 14px;
                padding: 10px 16px;
                font-weight: 600;
                font-size: 14px;
            }
            QPushButton:hover {
                background: #005BBB;
            }
            QPushButton:pressed {
                background: #004C99;
            }
            QFrame#sep {
                background: rgba(209, 209, 214, 0.7);
                max-height: 1px;
            }
        """)

    def encrypt(self):
        text = self.input_text.toPlainText().strip()
        key = self.key_text.text().strip()
        if not text or not key:
            self.output_text.setPlainText("Veuillez entrer le texte et la clé.")
            return
        result = encrypt_all(text, key)
        self.output_text.setPlainText(result)

    def decrypt(self):
        text = self.input_text.toPlainText().strip()
        key = self.key_text.text().strip()
        if not text or not key:
            self.output_text.setPlainText("Veuillez entrer le texte et la clé.")
            return
        try:
            result = decrypt_all(text, key)
            self.output_text.setPlainText(result)
        except Exception:
            self.output_text.setPlainText("Erreur de déchiffrement. Vérifie la clé et le texte.")

    # window drag
    def mousePressEvent(self, event):
        if event.button() == QtCore.Qt.MouseButton.LeftButton:
            self.old_pos = event.globalPosition().toPoint()

    def mouseMoveEvent(self, event):
        if self.old_pos:
            delta = event.globalPosition().toPoint() - self.old_pos
            self.move(self.x() + delta.x(), self.y() + delta.y())
            self.old_pos = event.globalPosition().toPoint()

    def mouseReleaseEvent(self, event):
        self.old_pos = None


if __name__ == "__main__":
    app = QApplication([])
    window = MacWindow()
    window.show()
    app.exec()
