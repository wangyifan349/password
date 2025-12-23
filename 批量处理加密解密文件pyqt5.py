import os
import sys
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QFileDialog, QTextEdit, QProgressBar, QMessageBox, QSizePolicy, QSpacerItem, QDialog, QTextBrowser
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QColor, QTextCharFormat, QTextCursor
from concurrent.futures import ThreadPoolExecutor
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes

PBKDF2_ITERATIONS = 100_000
KEY_SIZE = 32
SALT_SIZE = 16
NONCE_SIZE = 12

def get_all_files_in_directory(directory_path):
    file_list = []
    for current_directory_path, _, file_name_list in os.walk(directory_path):
        for file_name in file_name_list:
            full_path = os.path.join(current_directory_path, file_name)
            file_list.append(full_path)
    return file_list
def derive_key(password, salt):
    return PBKDF2(password.encode('utf-8'), salt, dkLen=KEY_SIZE, count=PBKDF2_ITERATIONS)
def encrypt_file(file_path, password):
    salt = get_random_bytes(SALT_SIZE)
    key = derive_key(password, salt)
    cipher = ChaCha20_Poly1305.new(key=key)
    nonce = cipher.nonce
    with open(file_path, 'rb') as file_input:
        plain_data = file_input.read()
    encrypted_data, tag = cipher.encrypt_and_digest(plain_data)
    with open(file_path, 'wb') as file_output:
        file_output.write(salt + nonce + tag + encrypted_data)
def decrypt_file(file_path, password):
    with open(file_path, 'rb') as file_input:
        salt = file_input.read(SALT_SIZE)
        nonce = file_input.read(NONCE_SIZE)
        tag = file_input.read(16)
        encrypted_data = file_input.read()
    key = derive_key(password, salt)
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    plain_data = cipher.decrypt_and_verify(encrypted_data, tag)
    with open(file_path, 'wb') as file_output:
        file_output.write(plain_data)
class EncryptorWorker(QThread):
    progress_signal = pyqtSignal(int)
    success_signal = pyqtSignal(str)
    error_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(str)

    def __init__(self, directory_path, password, mode):
        super().__init__()
        self.directory_path = directory_path
        self.password = password
        self.mode = mode
        self.executor = ThreadPoolExecutor(max_workers=os.cpu_count())

    def run(self):
        file_list = get_all_files_in_directory(self.directory_path)
        total_files_count = len(file_list)
        completed_files_count = 0
        def process_one_file(file_path):
            nonlocal completed_files_count
            try:
                if self.mode == 'encrypt':
                    encrypt_file(file_path, self.password)
                else:
                    decrypt_file(file_path, self.password)
                self.success_signal.emit(f"OK: {file_path}")
            except Exception as exception_info:
                self.error_signal.emit(f"FAILED: {file_path}, {exception_info}")
            finally:
                completed_files_count += 1
                percent_progress = int((completed_files_count / total_files_count) * 100)
                self.progress_signal.emit(percent_progress)
        future_list = []
        for file_path in file_list:
            future_task = self.executor.submit(process_one_file, file_path)
            future_list.append(future_task)
        for future_task in future_list:
            future_task.result()
        self.finished_signal.emit("All files processed.")

class DonationDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Support & Donate")
        self.setMinimumSize(440, 240)
        font_main = QFont("Arial", 12)
        layout = QVBoxLayout()
        label = QLabel("If you found this tool helpful, you can support me!\n")
        label.setFont(font_main)
        layout.addWidget(label, alignment=Qt.AlignHCenter)
        browser = QTextBrowser()
        browser.setFont(QFont("Consolas", 13))
        browser.setPlainText(
            "Bitcoin address:\n  bc1Xxxxxcccc\n\n"
            "Ethereum address:\n  0xYYYYYYyy222233334444...\n\n"
            "Thank you for your donation!"
        )
        layout.addWidget(browser)
        self.setLayout(layout)
class EncryptorApp(QWidget):
    def __init__(self):
        super().__init__()
        self.worker = None
        self.init_ui()
    def init_ui(self):
        self.setWindowTitle("ChaCha20-Poly1305 Batch File Encryptor (Beautiful Edition)")
        self.setMinimumWidth(700)
        self.setMinimumHeight(360)
        font_main = QFont("Arial", 13)
        outer_layout = QVBoxLayout()
        outer_layout.setContentsMargins(28, 16, 28, 16)
        outer_layout.setSpacing(16)
        directory_layout = QHBoxLayout()
        label_directory = QLabel('Target Directory:')
        label_directory.setFont(font_main)
        self.input_directory = QLineEdit()
        self.input_directory.setReadOnly(True)
        self.input_directory.setFont(font_main)
        self.input_directory.setMinimumWidth(350)
        button_browse = QPushButton('Browse')
        button_browse.setFont(font_main)
        button_browse.clicked.connect(self.select_directory)
        directory_layout.addSpacerItem(QSpacerItem(20, 20, QSizePolicy.Expanding, QSizePolicy.Minimum))
        directory_layout.addWidget(label_directory)
        directory_layout.addWidget(self.input_directory)
        directory_layout.addWidget(button_browse)
        directory_layout.addSpacerItem(QSpacerItem(20, 20, QSizePolicy.Expanding, QSizePolicy.Minimum))
        outer_layout.addLayout(directory_layout)
        password_layout = QHBoxLayout()
        label_password = QLabel('Password:')
        label_password.setFont(font_main)
        self.input_password = QLineEdit()
        self.input_password.setEchoMode(QLineEdit.Password)
        self.input_password.setFont(font_main)
        self.input_password.setMinimumWidth(200)
        password_layout.addSpacerItem(QSpacerItem(20, 20, QSizePolicy.Expanding, QSizePolicy.Minimum))
        password_layout.addWidget(label_password)
        password_layout.addWidget(self.input_password)
        password_layout.addSpacerItem(QSpacerItem(20, 20, QSizePolicy.Expanding, QSizePolicy.Minimum))
        outer_layout.addLayout(password_layout)
        button_layout = QHBoxLayout()
        button_encrypt = QPushButton('Encrypt')
        button_encrypt.setFont(QFont("Arial", 13, QFont.Bold))
        button_decrypt = QPushButton('Decrypt')
        button_decrypt.setFont(QFont("Arial", 13, QFont.Bold))
        button_donate = QPushButton('Donate')
        button_donate.setFont(QFont("Arial", 13))
        button_encrypt.setMinimumWidth(120)
        button_decrypt.setMinimumWidth(120)
        button_donate.setMinimumWidth(120)
        button_encrypt.clicked.connect(self.start_encryption)
        button_decrypt.clicked.connect(self.start_decryption)
        button_donate.clicked.connect(self.show_donation_dialog)
        button_layout.addSpacerItem(QSpacerItem(20, 20, QSizePolicy.Expanding, QSizePolicy.Minimum))
        button_layout.addWidget(button_encrypt)
        button_layout.addWidget(button_decrypt)
        button_layout.addWidget(button_donate)
        button_layout.addSpacerItem(QSpacerItem(20, 20, QSizePolicy.Expanding, QSizePolicy.Minimum))
        outer_layout.addLayout(button_layout)
        self.progress_bar = QProgressBar()
        self.progress_bar.setFont(font_main)
        self.progress_bar.setAlignment(Qt.AlignCenter)
        self.progress_bar.setFixedHeight(28)
        outer_layout.addWidget(self.progress_bar)
        self.log_box = QTextEdit()
        self.log_box.setFont(QFont("Consolas", 12))
        self.log_box.setReadOnly(True)
        self.log_box.setMinimumHeight(100)
        self.log_box.setTextColor(QColor("navy"))
        outer_layout.addWidget(self.log_box)
        self.setLayout(outer_layout)
        self.center_window()

    def center_window(self):
        screen_geometry = QApplication.desktop().screenGeometry()
        window_geometry = self.geometry()
        self.move(
            (screen_geometry.width() - window_geometry.width()) // 2,
            (screen_geometry.height() - window_geometry.height()) // 2
        )

    def select_directory(self):
        directory = QFileDialog.getExistingDirectory(self, 'Choose Directory')
        if directory:
            self.input_directory.setText(directory)

    def start_encryption(self):
        self.start_task('encrypt')

    def start_decryption(self):
        self.start_task('decrypt')

    def show_donation_dialog(self):
        donation_dialog = DonationDialog(self)
        donation_dialog.exec_()

    def start_task(self, mode):
        directory = self.input_directory.text()
        password = self.input_password.text()
        if not directory or not password:
            QMessageBox.warning(self, 'Warning', 'Please select a directory and enter password.')
            return
        self.progress_bar.setValue(0)
        self.log_box.clear()
        self.append_log(f"Start {mode}ing...", QColor("navy"))

        self.worker = EncryptorWorker(directory, password, mode)
        self.worker.progress_signal.connect(self.progress_bar.setValue)
        self.worker.success_signal.connect(lambda message: self.append_log(message, QColor("darkgreen")))
        self.worker.error_signal.connect(lambda message: self.append_log(message, QColor("red")))
        self.worker.finished_signal.connect(self.task_finished)
        self.worker.start()

    def append_log(self, message, color):
        text_cursor = self.log_box.textCursor()
        text_format = QTextCharFormat()
        text_format.setForeground(color)
        text_cursor.movePosition(QTextCursor.End)
        text_cursor.insertText(message + '\n', text_format)
        self.log_box.setTextCursor(text_cursor)
        self.log_box.ensureCursorVisible()

    def task_finished(self, message):
        self.append_log(message, QColor("blue"))
        QMessageBox.information(self, 'Done', message)
def main():
    application = QApplication(sys.argv)
    main_window = EncryptorApp()
    main_window.show()
    sys.exit(application.exec_())
if __name__ == '__main__':
    main()
