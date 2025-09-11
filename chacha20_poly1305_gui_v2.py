#!/usr/bin/env python3
# chacha20_poly1305_gui_v2.py
# Requirements: pycryptodome, PyQt5
# pip install pycryptodome pyqt5
import sys
import os
import tempfile
import traceback
import threading
from functools import partial
from typing import List, Optional, Tuple

from PyQt5 import QtWidgets, QtGui, QtCore
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256

# ---------- Crypto constants ----------
NONCE_SIZE = 12
TAG_SIZE = 16
SALT_SIZE = 16
DEFAULT_PBKDF2_ITERS = 10000  # as requested
# ---------- Utility crypto functions ----------
def derive_key_from_password(password: str, salt: Optional[bytes] = None, iterations: int = DEFAULT_PBKDF2_ITERS) -> Tuple[bytes, bytes]:
    if salt is None:
        salt = get_random_bytes(SALT_SIZE)
    key = PBKDF2(password.encode('utf-8'), salt, dkLen=32, count=iterations, hmac_hash_module=SHA256)
    return key, salt
def _atomic_write(path: str, data: bytes):
    dirn = os.path.dirname(path) or '.'
    fd, tmp = tempfile.mkstemp(dir=dirn)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except Exception:
                pass
def encrypt_file(in_path: str, out_path: str, key: bytes, aad: Optional[bytes] = None, write_salt: Optional[bytes] = None):
    nonce = get_random_bytes(NONCE_SIZE)
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    if aad:
        cipher.update(aad)
    with open(in_path, 'rb') as f:
        plaintext = f.read()
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    parts = []
    if write_salt:
        if len(write_salt) > 255:
            raise ValueError("salt too long")
        parts.append(bytes([len(write_salt)]))
        parts.append(write_salt)
    parts.append(nonce)
    parts.append(ciphertext)
    parts.append(tag)
    outdata = b''.join(parts)
    _atomic_write(out_path, outdata)
    # attempt to wipe plaintext/ciphertext variables
    try:
        del plaintext, ciphertext
    except Exception:
        pass

def decrypt_file(in_path: str, out_path: str, key: bytes, aad: Optional[bytes] = None):
    with open(in_path, 'rb') as f:
        data = f.read()
    idx = 0
    salt = None
    if len(data) >= 1:
        slen = data[0]
        # heuristic: if slen plausible and remaining length matches at least salt+nonce+tag
        if slen > 0 and len(data) >= 1 + slen + NONCE_SIZE + TAG_SIZE:
            # treat as having salt prefix
            idx = 1 + slen
            salt = data[1:1 + slen]
    if len(data) < idx + NONCE_SIZE + TAG_SIZE:
        raise ValueError("文件太短或格式不正确")
    nonce = data[idx: idx + NONCE_SIZE]; idx += NONCE_SIZE
    tag = data[-TAG_SIZE:]
    ciphertext = data[idx:-TAG_SIZE]
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    if aad:
        cipher.update(aad)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    _atomic_write(out_path, plaintext)
    try:
        del plaintext, ciphertext
    except Exception:
        pass
    return salt  # for information (not used here)

# ---------- Worker and signals ----------

class WorkerSignals(QtCore.QObject):
    progress = QtCore.pyqtSignal(int, int)  # done, total
    log = QtCore.pyqtSignal(str)
    finished = QtCore.pyqtSignal()
    error = QtCore.pyqtSignal(str)
class FileTask(QtCore.QRunnable):
    def __init__(self, filepath: str, out_path: str, mode: str, key: bytes, aad: Optional[bytes], write_salt: Optional[bytes], overwrite: bool):
        super().__init__()
        self.filepath = filepath
        self.out_path = out_path
        self.mode = mode
        self.key = key
        self.aad = aad
        self.write_salt = write_salt
        self.overwrite = overwrite
        self.signals = WorkerSignals()

    @QtCore.pyqtSlot()
    def run(self):
        try:
            if self.mode == 'encrypt':
                # if overwrite requested and same path, write to temp then replace
                encrypt_file(self.filepath, self.out_path, self.key, aad=self.aad, write_salt=self.write_salt)
                self.signals.log.emit(f"Encrypted: {os.path.basename(self.filepath)}")
            else:
                decrypt_file(self.filepath, self.out_path, self.key, aad=self.aad)
                self.signals.log.emit(f"Decrypted: {os.path.basename(self.filepath)}")
        except Exception as e:
            tb = traceback.format_exc()
            self.signals.log.emit(f"Error {os.path.basename(self.filepath)}: {e}\n{tb}")
            self.signals.error.emit(str(e))
        finally:
            self.signals.progress.emit(1, 1)
# ---------- Main Window ----------
  class DropListWidget(QtWidgets.QListWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.setSelectionMode(QtWidgets.QAbstractItemView.ExtendedSelection)
    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()
    def dragMoveEvent(self, e):
        e.acceptProposedAction()
    def dropEvent(self, e):
        urls = e.mimeData().urls()
        for u in urls:
            p = u.toLocalFile()
            if os.path.isdir(p):
                # add files recursively
                for root, _, files in os.walk(p):
                    for fn in files:
                        self.addItem(os.path.join(root, fn))
            else:
                self.addItem(p)
class MainWindow(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ChaCha20-Poly1305 批量加解密（改进版）")
        self.resize(820, 560)
        self.setWindowIcon(QtGui.QIcon.fromTheme("security"))
        # Widgets
        self.file_list = DropListWidget()
        self.add_btn = QtWidgets.QPushButton("添加文件/文件夹")
        self.remove_btn = QtWidgets.QPushButton("移除所选")
        self.clear_btn = QtWidgets.QPushButton("清空")
        self.mode_label = QtWidgets.QLabel("模式：")
        self.mode_combo = QtWidgets.QComboBox()
        self.mode_combo.addItems(["encrypt", "decrypt"])
        self.out_dir_label = QtWidgets.QLabel("输出目录（或勾选覆盖源文件）：")
        self.out_dir_edit = QtWidgets.QLineEdit()
        self.out_dir_btn = QtWidgets.QPushButton("选择目录")
        self.overwrite_chk = QtWidgets.QCheckBox("覆盖源文件（谨慎）")
        self.password_label = QtWidgets.QLabel("密码（派生 32 字节密钥，PBKDF2 迭代 10000）：")
        self.password_edit = QtWidgets.QLineEdit()
        self.password_edit.setEchoMode(QtWidgets.QLineEdit.Password)
        self.derive_btn = QtWidgets.QPushButton("派生并显示盐")
        self.salt_label = QtWidgets.QLabel("盐（hex，可留空以自动生成并写入文件）")
        self.salt_edit = QtWidgets.QLineEdit()
        self.aad_label = QtWidgets.QLabel("关联数据（AAD，可选）")
        self.aad_edit = QtWidgets.QLineEdit()
        self.threads_label = QtWidgets.QLabel("并发线程数：")
        self.threads_spin = QtWidgets.QSpinBox()
        self.threads_spin.setRange(1, 16)
        self.threads_spin.setValue(4)
        self.start_btn = QtWidgets.QPushButton("开始")
        self.cancel_btn = QtWidgets.QPushButton("取消")
        self.cancel_btn.setEnabled(False)
        self.progress_bar = QtWidgets.QProgressBar()
        self.log_box = QtWidgets.QPlainTextEdit()
        self.log_box.setReadOnly(True)
        # Layouts
        top_h = QtWidgets.QHBoxLayout()
        left_v = QtWidgets.QVBoxLayout()
        left_v.addWidget(QtWidgets.QLabel("文件列表（可拖放文件/文件夹）："))
        left_v.addWidget(self.file_list)
        left_btns = QtWidgets.QHBoxLayout()
        left_btns.addWidget(self.add_btn)
        left_btns.addWidget(self.remove_btn)
        left_btns.addWidget(self.clear_btn)
        left_v.addLayout(left_btns)
        right_v = QtWidgets.QVBoxLayout()
        form = QtWidgets.QGridLayout()
        form.addWidget(self.mode_label, 0, 0)
        form.addWidget(self.mode_combo, 0, 1)
        form.addWidget(self.out_dir_label, 1, 0)
        form.addWidget(self.out_dir_edit, 1, 1)
        form.addWidget(self.out_dir_btn, 1, 2)
        form.addWidget(self.overwrite_chk, 2, 1)
        form.addWidget(self.password_label, 3, 0)
        form.addWidget(self.password_edit, 3, 1)
        form.addWidget(self.derive_btn, 3, 2)
        form.addWidget(self.salt_label, 4, 0)
        form.addWidget(self.salt_edit, 4, 1, 1, 2)
        form.addWidget(self.aad_label, 5, 0)
        form.addWidget(self.aad_edit, 5, 1, 1, 2)
        form.addWidget(self.threads_label, 6, 0)
        form.addWidget(self.threads_spin, 6, 1)
        right_v.addLayout(form)
        action_h = QtWidgets.QHBoxLayout()
        action_h.addWidget(self.start_btn)
        action_h.addWidget(self.cancel_btn)
        right_v.addLayout(action_h)
        right_v.addWidget(self.progress_bar)
        right_v.addWidget(QtWidgets.QLabel("日志："))
        right_v.addWidget(self.log_box)
        top_h.addLayout(left_v, 2)
        top_h.addLayout(right_v, 3)
        self.setLayout(top_h)
        # Thread pool
        self.pool = QtCore.QThreadPool()
        self.tasks_total = 0
        self.tasks_done = 0
        self.active_tasks = []
        self.cancel_flag = threading.Event()
        # Connections
        self.add_btn.clicked.connect(self.add_files_dialog)
        self.remove_btn.clicked.connect(self.remove_selected)
        self.clear_btn.clicked.connect(self.file_list.clear)
        self.out_dir_btn.clicked.connect(self.select_out_dir)
        self.start_btn.clicked.connect(self.start)
        self.cancel_btn.clicked.connect(self.cancel)
        self.derive_btn.clicked.connect(self.derive_and_show_salt)
    # ---------- UI helpers ----------
    def add_files_dialog(self):
        paths, _ = QtWidgets.QFileDialog.getOpenFileNames(self, "选择文件（可多选）")
        for p in paths:
            self.file_list.addItem(p)
        # allow directory selection too
        d = QtWidgets.QFileDialog.getExistingDirectory(self, "或选择文件夹（取消以跳过）")
        if d:
            for root, _, files in os.walk(d):
                for fn in files:
                    self.file_list.addItem(os.path.join(root, fn))
    def remove_selected(self):
        for it in self.file_list.selectedItems():
            self.file_list.takeItem(self.file_list.row(it))
    def select_out_dir(self):
        d = QtWidgets.QFileDialog.getExistingDirectory(self, "选择输出目录")
        if d:
            self.out_dir_edit.setText(d)
    def derive_and_show_salt(self):
        pwd = self.password_edit.text()
        if not pwd:
            QtWidgets.QMessageBox.warning(self, "错误", "请输入密码以派生密钥")
            return
        key, salt = derive_key_from_password(pwd)
        self.log_box.appendPlainText(f"派生密钥(hex): {key.hex()}")
        self.log_box.appendPlainText(f"派生盐(hex): {salt.hex()}")
        self.salt_edit.setText(salt.hex())
        # overwrite local variables
        try:
            pwd = None
        except Exception:
            pass
    # ---------- Start / Cancel ----------
    def start(self):
        files = [self.file_list.item(i).text() for i in range(self.file_list.count())]
        if not files:
            QtWidgets.QMessageBox.warning(self, "错误", "请添加要处理的文件")
            return
        out_dir = self.out_dir_edit.text().strip()
        overwrite = self.overwrite_chk.isChecked()
        if not overwrite and (not out_dir or not os.path.isdir(out_dir)):
            QtWidgets.QMessageBox.warning(self, "错误", "请选择有效输出目录或勾选覆盖源文件")
            return
        password = self.password_edit.text()
        if not password:
            QtWidgets.QMessageBox.warning(self, "错误", "请输入密码")
            return
        # derive key (if salt provided, use it; else generate and will be written to files)
        salt_hex = self.salt_edit.text().strip()
        write_salt = None
        if salt_hex:
            try:
                salt_bytes = bytes.fromhex(salt_hex)
                key, _ = derive_key_from_password(password, salt=salt_bytes)
                write_salt = None  # do not write salt into output when user provided salt
            except Exception:
                QtWidgets.QMessageBox.warning(self, "错误", "盐不是合法 hex")
                return
        else:
            key, gen_salt = derive_key_from_password(password)
            write_salt = gen_salt  # will be written to each encrypted file
        aad = self.aad_edit.text().encode('utf-8') if self.aad_edit.text() else None
        # security: attempt to wipe password variable
        try:
            self.password_edit.clear()
            password = None
        except Exception:
            pass
        mode = self.mode_combo.currentText()
        threads = self.threads_spin.value()
        self.pool.setMaxThreadCount(threads)
        # prepare tasks
        tasks = []
        for p in files:
            base = os.path.basename(p)
            if overwrite:
                out_path = p + ".tmp"
                final_out = p
            else:
                out_name = base + (".enc" if mode == 'encrypt' else ".dec")
                out_path = os.path.join(out_dir, out_name)
                final_out = out_path
            # if overwriting, write to temp then replace
            task = FileTask(filepath=p, out_path=out_path, mode=mode, key=key, aad=aad, write_salt=write_salt, overwrite=overwrite)
            # connect signals
            task.signals.progress.connect(self._on_task_progress)
            task.signals.log.connect(self._on_task_log)
            task.signals.error.connect(self._on_task_error)
            tasks.append((task, p, out_path, final_out))
        self.tasks_total = len(tasks)
        self.tasks_done = 0
        self.progress_bar.setMaximum(self.tasks_total)
        self.progress_bar.setValue(0)
        self.log_box.appendPlainText(f"开始任务：{self.tasks_total} 个文件，线程数 {threads}")
        self.start_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)
        self.cancel_flag.clear()
        self.active_tasks = []
        # submit tasks
        for task, src, tmp_out, final_out in tasks:
            if self.cancel_flag.is_set():
                break
            self.pool.start(task)
            self.active_tasks.append((task, src, tmp_out, final_out))
        # start a monitor timer to check completion and perform final moves for overwrite
        self._monitor_timer = QtCore.QTimer()
        self._monitor_timer.setInterval(500)
        self._monitor_timer.timeout.connect(self._monitor)
        self._monitor_timer.start()
    def cancel(self):
        self.cancel_flag.set()
        self.log_box.appendPlainText("已请求取消；正在等待进行中的任务完成...")
        self.cancel_btn.setEnabled(False)
    # ---------- Task callbacks ----------
    def _on_task_progress(self, done: int, total: int):
        # each task emits (1,1) on completion; increment overall counter
        self.tasks_done += 1
        self.progress_bar.setValue(self.tasks_done)
        if self.tasks_done >= self.tasks_total:
            # finalization handled in monitor
            pass
    def _on_task_log(self, msg: str):
        self.log_box.appendPlainText(msg)
    def _on_task_error(self, err: str):
        self.log_box.appendPlainText("任务错误: " + err)
    def _monitor(self):
        # check if all tasks finished by comparing progress
        if self.tasks_done >= self.tasks_total or (self.cancel_flag.is_set() and all(not self._is_task_running(t[0]) for t in self.active_tasks)):
            self._monitor_timer.stop()
            # for overwrite operations, move tmp files to final targets
            for task, src, tmp_out, final_out in list(self.active_tasks):
                if os.path.exists(tmp_out):
                    try:
                        # if final exists, make a backup before replace
                        if final_out != tmp_out and os.path.exists(final_out):
                            bak = final_out + ".bak"
                            os.replace(final_out, bak)
                        os.replace(tmp_out, final_out)
                        self.log_box.appendPlainText(f"已写入：{final_out}")
                    except Exception as e:
                        self.log_box.appendPlainText(f"替换失败 {final_out}: {e}")
            self.start_btn.setEnabled(True)
            self.cancel_btn.setEnabled(False)
            self.log_box.appendPlainText("所有任务完成或已取消。")
            # try to wipe key variable
            try:
                # attempt overwrite
                # key was stored in local var inside start; here we attempt to remove references in tasks
                for t, *_ in self.active_tasks:
                    try:
                        t.key = b'\x00' * 32
                    except Exception:
                        pass
                self.active_tasks = []
            except Exception:
                pass
    def _is_task_running(self, task: FileTask) -> bool:
        # no direct API; assume tasks running if not yet signaled via progress increment.
        # For simplicity, return False if tasks_done >= total (monitored elsewhere)
        return False
def main():
    app = QtWidgets.QApplication(sys.argv)
    w = MainWindow()
    w.show()
    sys.exit(app.exec_())
if __name__ == '__main__':
    main()
