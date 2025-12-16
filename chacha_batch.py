#!/usr/bin/env python3
import os
import sys
import tempfile
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes
import base58
NONCE_SIZE = 12
KEY_SIZE = 32
TAG_SIZE = 16
MAX_WORKERS = min(32, (os.cpu_count() or 4) * 5)
def derive_key_from_password(password: str) -> bytes:
    return hashlib.sha512(password.encode()).digest()[:KEY_SIZE]
def encrypt_file_inplace_base58(path, key):
    with open(path, "rb") as f:
        plaintext = f.read()
    nonce = get_random_bytes(NONCE_SIZE)
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    payload = nonce + ciphertext + tag
    encoded = base58.b58encode(payload).decode('ascii')
    tmp_fd, tmp_path = tempfile.mkstemp(dir=os.path.dirname(path))
    with os.fdopen(tmp_fd, "w", encoding="utf-8") as tf:
        tf.write(encoded)
    os.replace(tmp_path, path)
def decrypt_file_inplace_base58(path, key):
    with open(path, "r", encoding="utf-8") as f:
        text = f.read().strip()
    data = base58.b58decode(text)
    if len(data) < NONCE_SIZE + TAG_SIZE:
        raise ValueError("输入文件太短，无法解密")
    nonce = data[:NONCE_SIZE]
    tag = data[-TAG_SIZE:]
    ciphertext = data[NONCE_SIZE:-TAG_SIZE]
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    tmp_fd, tmp_path = tempfile.mkstemp(dir=os.path.dirname(path))
    with os.fdopen(tmp_fd, "wb") as tf:
        tf.write(plaintext)
    os.replace(tmp_path, path)
def _task_process(task):
    path = task["path"]
    key = task["key"]
    mode = task["mode"]
    if mode == "encrypt":
        encrypt_file_inplace_base58(path, key)
        return f"[OK] Encrypted (base58): {path}"
    else:
        decrypt_file_inplace_base58(path, key)
        return f"[OK] Decrypted: {path}"
def process_dir_inplace(src_dir, key, mode="encrypt", max_workers=MAX_WORKERS):
    src_dir = os.path.abspath(src_dir)
    tasks = []
    for root, dirs, files in os.walk(src_dir):
        for fname in files:
            if fname.startswith("."):
                continue
            tasks.append({"path": os.path.join(root, fname), "key": key, "mode": mode})
    if not tasks:
        print("没有待处理的文件。")
        return
    workers = min(max_workers, len(tasks))
    with ThreadPoolExecutor(max_workers=workers) as exe:
        futures = {exe.submit(_task_process, t): t for t in tasks}
        for fut in as_completed(futures):
            try:
                msg = fut.result()
                print(msg)
            except Exception as e:
                print(f"[ERR] {futures[fut]['path']}: {e}")
def interactive_menu():
    while True:
        print("\n==== ChaCha20-Poly1305 批量加解密 CLI （覆盖 + Base58 输出） ====")
        print("1) 加密目录（覆盖原文件为 Base58 文本）")
        print("2) 解密目录（从 Base58 文本还原二进制，覆盖原文件）")
        print("3) 退出")
        choice = input("选择编号: ").strip()
        if choice in ("1", "2"):
            mode = "encrypt" if choice == "1" else "decrypt"
            src = input("目标目录 (将被遍历并直接覆盖文件): ").strip()
            if not src or not os.path.isdir(src):
                print("无效目录。")
                continue
            pwd = input("输入密码（明文，将用 SHA-512 派生密钥）: ")
            if not pwd:
                print("密码不能为空。")
                continue
            key = derive_key_from_password(pwd)
            print(f"开始{'加密' if mode=='encrypt' else '解密'} ... （并发 workers={MAX_WORKERS}）")
            process_dir_inplace(src, key, mode=mode)
            print("完成。")
        elif choice == "3":
            print("退出。")
            break
        else:
            print("无效选择，请输入 1-3。")
if __name__ == "__main__":
    try:
        interactive_menu()
    except KeyboardInterrupt:
        print("\n已中断，退出。")
        sys.exit(0)
