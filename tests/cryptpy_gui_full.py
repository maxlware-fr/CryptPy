from PyQt6 import QtWidgets, QtCore, QtGui
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QLabel, QLineEdit, QPushButton,
    QVBoxLayout, QWidget, QHBoxLayout, QFrame, QTextEdit,
    QGraphicsBlurEffect, QCheckBox, QFileDialog, QListWidget,
    QListWidgetItem, QSpinBox
)
import base64, hashlib, random, string, json
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

def generate_key(length):
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(chars) for _ in range(length))


class CryptPyApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CryptPy")
        self.setFixedSize(860, 620)
        self.setWindowFlag(QtCore.Qt.WindowType.FramelessWindowHint)
        self.setAttribute(QtCore.Qt.WidgetAttribute.WA_TranslucentBackground)

        self.dark_mode = False
        self.old_pos = None

        self.history = []
        self.preferences = {
            "auto_copy": True,
            "auto_clear": False,
            "dark_mode_auto": True
        }

        self.init_ui()
        self.apply_styles()
        self.apply_auto_theme()

    def init_ui(self):
        self.container = QWidget()
        self.container.setObjectName("container")
        self.setCentralWidget(self.container)

        self.bg = QWidget(self.container)
        self.bg.setObjectName("background")
        self.bg.setGeometry(0, 0, 860, 620)

        blur = QGraphicsBlurEffect()
        blur.setBlurRadius(16)
        self.bg.setGraphicsEffect(blur)

        self.content = QWidget(self.container)
        self.content.setObjectName("content")
        self.content.setGeometry(0, 0, 860, 620)

        layout = QVBoxLayout()
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(12)

        top_bar = QHBoxLayout()
        top_bar.setSpacing(10)

        self.red = self.make_circle("#FF5F57", "close")
        self.yellow = self.make_circle("#FFBD2E", "minimize")
        self.green = self.make_circle("#28C940", "maximize")

        top_bar.addWidget(self.red)
        top_bar.addWidget(self.yellow)
        top_bar.addWidget(self.green)
        top_bar.addStretch()

        layout.addLayout(top_bar)

        title = QLabel("CryptPy")
        title.setObjectName("title")

        subtitle = QLabel("Multi-layer encryption • César + Vigenère + Base64 + XOR + AES")
        subtitle.setObjectName("subtitle")

        layout.addWidget(title)
        layout.addWidget(subtitle)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setObjectName("sep")
        layout.addWidget(sep)

        # Input
        self.input_text = QTextEdit()
        self.input_text.setPlaceholderText("Texte à chiffrer/déchiffrer…")
        self.input_text.setFixedHeight(120)

        self.key_text = QLineEdit()
        self.key_text.setPlaceholderText("Clé secrète…")

        # Algo selection
        algo_layout = QHBoxLayout()
        self.cb_cesar = QCheckBox("César")
        self.cb_vigenere = QCheckBox("Vigenère")
        self.cb_base64 = QCheckBox("Base64")
        self.cb_xor = QCheckBox("XOR")
        self.cb_aes = QCheckBox("AES")

        self.cb_cesar.setChecked(True)
        self.cb_vigenere.setChecked(True)
        self.cb_base64.setChecked(True)
        self.cb_xor.setChecked(True)
        self.cb_aes.setChecked(True)

        algo_layout.addWidget(self.cb_cesar)
        algo_layout.addWidget(self.cb_vigenere)
        algo_layout.addWidget(self.cb_base64)
        algo_layout.addWidget(self.cb_xor)
        algo_layout.addWidget(self.cb_aes)

        # Buttons
        btn_layout = QHBoxLayout()
        self.encrypt_btn = QPushButton("Chiffrer")
        self.decrypt_btn = QPushButton("Déchiffrer")
        self.copy_btn = QPushButton("Copier")
        self.clear_btn = QPushButton("Effacer")
        self.theme_btn = QPushButton("Dark Mode")
        self.gen_btn = QPushButton("Générer clé")
        self.save_btn = QPushButton("Sauvegarder")
        self.load_btn = QPushButton("Charger")

        btn_layout.addWidget(self.encrypt_btn)
        btn_layout.addWidget(self.decrypt_btn)
        btn_layout.addWidget(self.copy_btn)
        btn_layout.addWidget(self.clear_btn)
        btn_layout.addWidget(self.theme_btn)
        btn_layout.addWidget(self.gen_btn)
        btn_layout.addWidget(self.save_btn)
        btn_layout.addWidget(self.load_btn)

        # Output
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setPlaceholderText("Résultat…")
        self.output_text.setFixedHeight(160)

        # History + log
        bottom_layout = QHBoxLayout()

        self.history_list = QListWidget()
        self.history_list.setFixedWidth(280)
        self.history_list.setObjectName("history")

        log_layout = QVBoxLayout()
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setFixedHeight(120)
        self.log_text.setPlaceholderText("Log…")

        self.auto_copy_cb = QCheckBox("Auto-copie")
        self.auto_clear_cb = QCheckBox("Auto-clear")
        self.auto_copy_cb.setChecked(self.preferences["auto_copy"])
        self.auto_clear_cb.setChecked(self.preferences["auto_clear"])

        log_layout.addWidget(self.log_text)
        log_layout.addWidget(self.auto_copy_cb)
        log_layout.addWidget(self.auto_clear_cb)

        bottom_layout.addWidget(self.history_list)
        bottom_layout.addLayout(log_layout)

        # Loading
        self.loading_label = QLabel("")
        self.loading_label.setObjectName("loading")

        layout.addWidget(self.input_text)
        layout.addWidget(self.key_text)
        layout.addLayout(algo_layout)
        layout.addLayout(btn_layout)
        layout.addWidget(self.output_text)
        layout.addLayout(bottom_layout)
        layout.addWidget(self.loading_label)

        self.content.setLayout(layout)

        self.encrypt_btn.clicked.connect(self.encrypt)
        self.decrypt_btn.clicked.connect(self.decrypt)
        self.copy_btn.clicked.connect(self.copy_result)
        self.clear_btn.clicked.connect(self.clear_all)
        self.theme_btn.clicked.connect(self.toggle_theme)
        self.gen_btn.clicked.connect(self.generate_key)
        self.save_btn.clicked.connect(self.save_file)
        self.load_btn.clicked.connect(self.load_file)
        self.history_list.itemClicked.connect(self.load_history_item)

        self.auto_copy_cb.stateChanged.connect(self.update_preferences)
        self.auto_clear_cb.stateChanged.connect(self.update_preferences)

    def make_circle(self, color, action):
        w = QLabel()
        w.setFixedSize(14, 14)
        w.setStyleSheet(f"background: {color}; border-radius: 7px;")
        w.mousePressEvent = lambda e: self.window_action(action)
        return w

    def window_action(self, action):
        if action == "close":
            self.close()
        elif action == "minimize":
            self.showMinimized()
        elif action == "maximize":
            if self.isMaximized():
                self.showNormal()
            else:
                self.showMaximized()

    def apply_styles(self):
        self.bg.setStyleSheet("""
            #background {
                background: rgba(255, 255, 255, 0.35);
                border-radius: 18px;
            }
        """)

        self.content.setStyleSheet("""
            #content {
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
            QLabel#loading {
                color: #6E6E73;
                font-size: 13px;
            }
            QListWidget#history {
                background: rgba(255,255,255,0.7);
                border: 1px solid rgba(209,209,214,0.8);
                border-radius: 14px;
                padding: 8px;
            }
        """)

    def apply_dark_styles(self):
        self.bg.setStyleSheet("""
            #background {
                background: rgba(28, 28, 30, 0.55);
                border-radius: 18px;
            }
        """)

        self.content.setStyleSheet("""
            #content {
                background: rgba(28, 28, 30, 0.85);
                border: 1px solid rgba(60, 60, 67, 0.8);
                border-radius: 18px;
            }
            QLabel#title {
                font-size: 24px;
                font-weight: 700;
                color: #FFFFFF;
            }
            QLabel#subtitle {
                font-size: 13px;
                color: #D1D1D6;
            }
            QLineEdit, QTextEdit {
                background: rgba(44, 44, 46, 0.75);
                border: 1px solid rgba(72, 72, 74, 0.9);
                border-radius: 14px;
                padding: 10px;
                font-size: 14px;
                color: #FFFFFF;
            }
            QPushButton {
                background: #0A84FF;
                color: white;
                border: none;
                border-radius: 14px;
                padding: 10px 16px;
                font-weight: 600;
                font-size: 14px;
            }
            QPushButton:hover {
                background: #0064D6;
            }
            QPushButton:pressed {
                background: #004AAB;
            }
            QFrame#sep {
                background: rgba(72, 72, 74, 0.8);
                max-height: 1px;
            }
            QLabel#loading {
                color: #D1D1D6;
                font-size: 13px;
            }
            QListWidget#history {
                background: rgba(44,44,46,0.75);
                border: 1px solid rgba(72,72,74,0.9);
                border-radius: 14px;
                padding: 8px;
            }
        """)

    def apply_auto_theme(self):
        # macOS auto dark mode
        if self.preferences["dark_mode_auto"]:
            try:
                from AppKit import NSApp, NSAppearance
                appearance = NSApp.effectiveAppearance().name()
                self.dark_mode = "Dark" in appearance
            except Exception:
                self.dark_mode = False

        if self.dark_mode:
            self.apply_dark_styles()
            self.theme_btn.setText("Light Mode")
        else:
            self.apply_styles()
            self.theme_btn.setText("Dark Mode")

    def update_preferences(self):
        self.preferences["auto_copy"] = self.auto_copy_cb.isChecked()
        self.preferences["auto_clear"] = self.auto_clear_cb.isChecked()

    def encrypt(self):
        self.loading("Chiffrement…")
        text = self.input_text.toPlainText().strip()
        key = self.key_text.text().strip()

        if not text or not key:
            self.log("Erreur : texte ou clé vide.")
            self.loading_done()
            return

        try:
            result = text
            steps = []

            if self.cb_cesar.isChecked():
                result = cesar_encrypt(result)
                steps.append("César")
            if self.cb_vigenere.isChecked():
                result = vigenere_encrypt(result, key)
                steps.append("Vigenère")
            if self.cb_base64.isChecked():
                result = base64_encrypt(result)
                steps.append("Base64")
            if self.cb_xor.isChecked():
                result = xor_encrypt(result, key)
                steps.append("XOR")
            if self.cb_aes.isChecked():
                result = aes_encrypt(result, key)
                steps.append("AES")

            self.output_text.setPlainText(result)
            self.log("Chiffrement OK • " + " > ".join(steps))
            self.push_history(result)

            if self.preferences["auto_copy"]:
                self.copy_result()

            if self.preferences["auto_clear"]:
                self.input_text.clear()

        except Exception as e:
            self.log(f"Erreur chiffrement : {e}")

        self.loading_done()

    def decrypt(self):
        self.loading("Déchiffrement…")
        text = self.input_text.toPlainText().strip()
        key = self.key_text.text().strip()

        if not text or not key:
            self.log("Erreur : texte ou clé vide.")
            self.loading_done()
            return

        try:
            result = text
            steps = []

            if self.cb_aes.isChecked():
                result = aes_decrypt(result, key)
                steps.append("AES")
            if self.cb_xor.isChecked():
                result = xor_decrypt(result, key)
                steps.append("XOR")
            if self.cb_base64.isChecked():
                result = base64_decrypt(result)
                steps.append("Base64")
            if self.cb_vigenere.isChecked():
                result = vigenere_decrypt(result, key)
                steps.append("Vigenère")
            if self.cb_cesar.isChecked():
                result = cesar_decrypt(result)
                steps.append("César")

            self.output_text.setPlainText(result)
            self.log("Déchiffrement OK • " + " > ".join(steps))
            self.push_history(result)

            if self.preferences["auto_copy"]:
                self.copy_result()

            if self.preferences["auto_clear"]:
                self.input_text.clear()

        except Exception as e:
            self.log(f"Erreur déchiffrement : {e}")

        self.loading_done()

    def copy_result(self):
        clipboard = QApplication.clipboard()
        clipboard.setText(self.output_text.toPlainText())
        self.log("Copié dans le presse-papier.")

    def clear_all(self):
        self.input_text.clear()
        self.key_text.clear()
        self.output_text.clear()
        self.log("Effacé.")

    def toggle_theme(self):
        self.dark_mode = not self.dark_mode
        if self.dark_mode:
            self.apply_dark_styles()
            self.theme_btn.setText("Light Mode")
        else:
            self.apply_styles()
            self.theme_btn.setText("Dark Mode")

    def generate_key(self):
        length, ok = QtWidgets.QInputDialog.getInt(self, "Générer clé", "Longueur :", 16, 8, 64, 1)
        if ok:
            key = generate_key(length)
            self.key_text.setText(key)
            self.log("Clé générée.")

    def save_file(self):
        path, _ = QFileDialog.getSaveFileName(self, "Sauvegarder", "", "Texte (*.txt)")
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.output_text.toPlainText())
            self.log("Sauvegardé : " + path)

    def load_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Charger", "", "Texte (*.txt)")
        if path:
            with open(path, "r", encoding="utf-8") as f:
                data = f.read()
            self.input_text.setPlainText(data)
            self.log("Chargé : " + path)

    def push_history(self, text):
        self.history.append(text)
        item = QListWidgetItem(text[:40] + ("..." if len(text) > 40 else ""))
        self.history_list.addItem(item)

    def load_history_item(self, item):
        index = self.history_list.row(item)
        self.input_text.setPlainText(self.history[index])
        self.log("Historique chargé.")

    def log(self, message):
        self.log_text.append(message)

    def loading(self, message):
        self.loading_label.setText(message)
        self.loading_dots = 0
        self.loading_timer = QtCore.QTimer()
        self.loading_timer.timeout.connect(self.update_loading)
        self.loading_timer.start(200)

    def update_loading(self):
        self.loading_dots = (self.loading_dots + 1) % 4
        self.loading_label.setText("Traitement" + "." * self.loading_dots)

    def loading_done(self):
        self.loading_timer.stop()
        self.loading_label.setText("")

    # Window drag
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
    window = CryptPyApp()
    window.show()
    app.exec()
