#!/usr/bin/env python3
"""
批量 AES-256-GCM 文件加密/解密（交互式菜单、密码派生、多线程）
依赖：pycryptodome
安装：pip install pycryptodome
"""
import os
import sys
from base64 import b64encode, b64decode
from hashlib import pbkdf2_hmac
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from concurrent.futures import ThreadPoolExecutor, as_completed
import multiprocessing
import getpass
import struct

PBKDF2_ITERATIONS = 200000
SALT_LEN = 16
KEY_LEN = 32
NONCE_LEN = 16  # PyCryptodome GCM nonce default length can be 16; will use cipher.nonce length
# File format (binary, all big-endian):
# 4 bytes magic b"AESG" | 1 byte version (1)
# 2 bytes header_len (unsigned short) | salt (16) | nonce_len (1) | nonce | header | ciphertext | tag_len (1) | tag
# tag_len for GCM tag is typically 16
MAGIC = b"AESG"
VERSION = 1
def derive_key(password_bytes, salt, iterations, key_len):
    return pbkdf2_hmac("sha256", password_bytes, salt, iterations, dklen=key_len)
def ensure_dir(path):
    if not os.path.exists(path):
        os.makedirs(path)
def pack_encrypted_blob(salt, nonce, header, ciphertext, tag):
    header_len = len(header)
    nonce_len = len(nonce)
    tag_len = len(tag)
    parts = []
    parts.append(MAGIC)
    parts.append(struct.pack(">B", VERSION))
    parts.append(struct.pack(">H", header_len))
    parts.append(salt)
    parts.append(struct.pack(">B", nonce_len))
    parts.append(nonce)
    parts.append(header)
    parts.append(ciphertext)
    parts.append(struct.pack(">B", tag_len))
    parts.append(tag)
    return b"".join(parts)
def unpack_encrypted_blob(data):
    off = 0
    if len(data) < 4 + 1 + 2 + SALT_LEN + 1 + 1:
        raise ValueError("数据太短")
    if data[off:off+4] != MAGIC:
        raise ValueError("魔数不匹配")
    off += 4
    version = data[off]
    if version != VERSION:
        raise ValueError("不支持的版本")
    off += 1
    header_len = struct.unpack_from(">H", data, off)[0]
    off += 2
    salt = data[off:off+SALT_LEN]
    off += SALT_LEN
    nonce_len = data[off]
    off += 1
    nonce = data[off:off+nonce_len]
    off += nonce_len
    header = data[off:off+header_len]
    off += header_len
    # ciphertext is until last byte tag_len and tag; need to read tag_len from end
    if off + 1 > len(data):
        raise ValueError("格式错误，缺少 tag 长度")
    # read tag_len from last byte
    tag_len = data[-1]
    if tag_len < 1 or tag_len > 64:
        raise ValueError("无效 tag 长度")
    tag = data[-1 - tag_len + 1:] if False else data[-tag_len:]
    # ciphertext is between off and len(data)-tag_len-1 (no extra byte after tag_len in this layout)
    ciphertext = data[off:len(data)-tag_len]
    return salt, nonce, header, ciphertext, tag
def encrypt_one_file(password_bytes, in_path, rel_path):
    tmp_path = in_path + ".tmp_encrypt"
    salt = get_random_bytes(SALT_LEN)
    key = derive_key(password_bytes, salt, PBKDF2_ITERATIONS, KEY_LEN)
    header = rel_path.encode("utf-8")
    inp = open(in_path, "rb")
    try:
        plaintext = inp.read()
    finally:
        inp.close()
    cipher = AES.new(key, AES.MODE_GCM)
    cipher.update(header)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    blob = pack_encrypted_blob(salt, cipher.nonce, header, ciphertext, tag)
    out = open(tmp_path, "wb")
    try:
        out.write(blob)
    finally:
        out.close()
    os.replace(tmp_path, in_path)
    return in_path
def decrypt_one_file(password_bytes, in_path):
    tmp_path = in_path + ".tmp_decrypt"
    inp = open(in_path, "rb")
    try:
        data = inp.read()
    finally:
        inp.close()
    # parse blob
    # manual parsing since ciphertext length variable; reuse unpack_encrypted_blob logic with safe parsing
    off = 0
    if len(data) < 4 + 1 + 2 + SALT_LEN + 1:
        raise ValueError("文件格式错误或太短")
    if data[off:off+4] != MAGIC:
        raise ValueError("魔数不匹配")
    off += 4
    version = data[off]
    if version != VERSION:
        raise ValueError("不支持的版本")
    off += 1
    header_len = struct.unpack_from(">H", data, off)[0]
    off += 2
    salt = data[off:off+SALT_LEN]
    off += SALT_LEN
    nonce_len = data[off]
    off += 1
    nonce = data[off:off+nonce_len]
    off += nonce_len
    header = data[off:off+header_len]
    off += header_len
    # remaining = ciphertext + tag
    remaining = data[off:]
    if len(remaining) < 1:
        raise ValueError("缺少 tag")
    # assume tag is last 16 bytes normally; but we stored tag as last N bytes and did not include explicit tag_len byte in end
    # To keep format robust, treat tag as last 16 bytes if length >=16, else error
    TAG_EXPECTED = 16
    if len(remaining) < TAG_EXPECTED:
        raise ValueError("剩余数据太短，缺少 tag")
    tag = remaining[-TAG_EXPECTED:]
    ciphertext = remaining[:-TAG_EXPECTED]
    key = derive_key(password_bytes, salt, PBKDF2_ITERATIONS, KEY_LEN)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(header)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    out = open(tmp_path, "wb")
    try:
        out.write(plaintext)
    finally:
        out.close()
    os.replace(tmp_path, in_path)
    return in_path
def gather_files_encrypt(input_dir):
    files = []
    for root, dirs, filenames in os.walk(input_dir):
        for fname in filenames:
            in_path = os.path.join(root, fname)
            rel_path = os.path.relpath(in_path, input_dir)
            files.append((in_path, rel_path))
    return files
def gather_files_decrypt(input_dir):
    files = []
    for root, dirs, filenames in os.walk(input_dir):
        for fname in filenames:
            in_path = os.path.join(root, fname)
            files.append(in_path)
    return files
def prompt_text(prompt):
    sys.stdout.write(prompt)
    sys.stdout.flush()
    return sys.stdin.readline().strip()
def prompt_int(prompt, default):
    while True:
        val = prompt_text(prompt + " [" + str(default) + "]: ")
        if val == "":
            return default
        try:
            n = int(val)
            if n > 0:
                return n
        except Exception:
            pass
        print("请输入正整数或回车使用默认。")
def run_encrypt(password, input_dir, workers):
    password_bytes = password.encode("utf-8")
    file_list = gather_files_encrypt(input_dir)
    if not file_list:
        print("没有找到要加密的文件。")
        return
    total = len(file_list)
    print("开始加密（覆盖源文件），文件数：", total, " 线程数：", workers)
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = []
        try:
            for in_path, rel_path in file_list:
                futures.append(executor.submit(encrypt_one_file, password_bytes, in_path, rel_path))
            completed = 0
            for fut in as_completed(futures):
                try:
                    src = fut.result()
                    completed += 1
                    print("[{}/{}] Encrypted: {}".format(completed, total, src))
                except Exception as e:
                    completed += 1
                    print("[{}/{}] Encrypt failed: {}".format(completed, total, str(e)))
        except KeyboardInterrupt:
            print("用户中断，加密停止。")
def run_decrypt(password, input_dir, workers):
    password_bytes = password.encode("utf-8")
    file_list = gather_files_decrypt(input_dir)
    if not file_list:
        print("没有找到要处理的文件。")
        return
    total = len(file_list)
    print("开始解密（覆盖源文件），文件数：", total, " 线程数：", workers)
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = []
        try:
            for in_path in file_list:
                futures.append(executor.submit(decrypt_one_file, password_bytes, in_path))
            completed = 0
            for fut in as_completed(futures):
                try:
                    src = fut.result()
                    completed += 1
                    print("[{}/{}] Decrypted: {}".format(completed, total, src))
                except Exception as e:
                    completed += 1
                    print("[{}/{}] Decrypt failed: {}".format(completed, total, str(e)))
        except KeyboardInterrupt:
            print("用户中断，解密停止。")
def main_menu():
    print("批量 AES-256-GCM 文件加密/解密（覆盖源文件）")
    print("1) 加密（encrypt）")
    print("2) 解密（decrypt）")
    print("3) 退出")
    choice = prompt_text("请选择操作 (1/2/3): ")
    return choice
def main():
    while True:
        choice = main_menu()
        if choice == "1":
            mode = "encrypt"
        elif choice == "2":
            mode = "decrypt"
        elif choice == "3":
            print("退出。")
            return
        else:
            print("无效选择。")
            continue
        input_dir = prompt_text("输入目录路径 (将对目录下所有文件覆盖操作): ")
        if input_dir == "":
            print("目录不能为空。")
            continue
        if not os.path.isdir(input_dir):
            print("目录不存在：", input_dir)
            continue
        pw_choice = prompt_text("是否隐藏输入口令？(y/n) [y]: ")
        if pw_choice == "" or pw_choice.lower().startswith("y"):
            try:
                password = getpass.getpass("输入口令: ")
            except Exception:
                password = prompt_text("输入口令: ")
        else:
            password = prompt_text("输入口令 (明文): ")

        if password == "":
            print("口令不能为空。")
            continue
        default_workers = multiprocessing.cpu_count()
        workers = prompt_int("设置并发线程数", default_workers)
        print("确认：模式 =", mode, ", 目录 =", input_dir, ", 线程 =", workers)
        ok = prompt_text("开始执行并覆盖源文件？(y/n) [n]: ")
        if ok != "" and ok.lower().startswith("y"):
            try:
                if mode == "encrypt":
                    run_encrypt(password, input_dir, workers)
                else:
                    run_decrypt(password, input_dir, workers)
            except KeyboardInterrupt:
                print("用户中断。")
        else:
            print("已取消该操作。")
if __name__ == "__main__":
    main()
