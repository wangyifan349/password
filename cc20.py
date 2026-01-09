from __future__ import annotations

import os
import struct
import hashlib
import getpass
import tempfile
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Tuple

# ========================
# 常量定义（格式参数和加密参数）
# ========================
MAGIC = b"CC20P13C"
VERSION = 3

FLAG_PASSWORD_KDF = 0x01
KDF_ID_PBKDF2_SHA256 = 0x01

KEY_SIZE = 32              # 密钥长度 32 字节（256 bit）
NONCE_SIZE = 12            # nonce 长度
TAG_SIZE = 16              # Poly1305 tag 长度
CHACHA_BLOCK_SIZE = 64     # ChaCha20 每个 block 字节数

DEFAULT_CHUNK_SIZE = 1024 * 1024         # 每个文件分块大小（1 MiB）
DEFAULT_PBKDF2_ITERATIONS = 300_000      # PBKDF2 默认迭代次数
DEFAULT_SALT_LENGTH = 16                 # salt 长度

# ========================
# 密钥派生：PBKDF2-HMAC-SHA256
# ========================
def derive_key_from_password(password: str, salt: bytes, iterations: int) -> bytes:
    """
    用 PBKDF2-HMAC-SHA256 以密码、salt 与迭代数派生 32 字节密钥
    password 编码必须为 utf-8，否则跨语言会不兼容
    """
    if password is None or password == "":
        raise ValueError("Password must be non-empty.")
    if iterations <= 0 or iterations > 0xFFFFFFFF:
        raise ValueError("PBKDF2 iterations out of range.")
    if salt is None or len(salt) < 8:
        raise ValueError("Salt too short.")
    password_bytes = password.encode("utf-8")
    key = hashlib.pbkdf2_hmac(
        "sha256",
        password_bytes,
        salt,
        iterations,
        dklen=KEY_SIZE
    )
    return key

def ensure_parent_directory(file_path: str) -> None:
    """
    保证输出文件的父目录已创建
    """
    parent_dir = os.path.dirname(file_path)
    if parent_dir:
        os.makedirs(parent_dir, exist_ok=True)

def is_encrypted_file(file_path: str) -> bool:
    """
    用于判断文件名后缀是否为 .cc20p13c（目录解密时用）
    """
    lower_name = file_path.lower()
    return lower_name.endswith(".cc20p13c")

def constant_time_equals(left: bytes, right: bytes) -> bool:
    """
    tag 常量时间比对，防止时延侧信道
    """
    if len(left) != len(right):
        return False
    diff = 0
    index = 0
    while index < len(left):
        diff |= left[index] ^ right[index]
        index += 1
    return diff == 0

def pad16(length: int) -> bytes:
    """
    Poly1305 MAC 输入按 RFC8439 需要补齐至 16 的整数倍
    """
    remainder = length % 16
    if remainder == 0:
        return b""
    return b"\x00" * (16 - remainder)

def pack_u32_le(value: int) -> bytes:
    return struct.pack("<I", value & 0xFFFFFFFF)

def pack_u64_le(value: int) -> bytes:
    return struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF)

def load_u32_le(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]

def rotate_left_u32(value: int, bits: int) -> int:
    """
    ChaCha20 需要 32 位整数左循环
    """
    value = value & 0xFFFFFFFF
    return ((value << bits) & 0xFFFFFFFF) | (value >> (32 - bits))

# ========================
# ChaCha20 算法实现 (RFC8439)
# ========================
def chacha20_quarter_round(a: int, b: int, c: int, d: int) -> Tuple[int, int, int, int]:
    """
    单个 quarter round 轮函数
    """
    a = (a + b) & 0xFFFFFFFF
    d = d ^ a
    d = rotate_left_u32(d, 16)

    c = (c + d) & 0xFFFFFFFF
    b = b ^ c
    b = rotate_left_u32(b, 12)

    a = (a + b) & 0xFFFFFFFF
    d = d ^ a
    d = rotate_left_u32(d, 8)

    c = (c + d) & 0xFFFFFFFF
    b = b ^ c
    b = rotate_left_u32(b, 7)

    return a, b, c, d

def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    """
    生成 64 字节 cha-cha20 keystream block，内部 20 轮
    """
    if key is None or len(key) != KEY_SIZE:
        raise ValueError("Key must be 32 bytes.")
    if nonce is None or len(nonce) != NONCE_SIZE:
        raise ValueError("Nonce must be 12 bytes.")

    state = [0] * 16
    # 固定字符串 expand 32-byte k
    state[0] = 0x61707865
    state[1] = 0x3320646e
    state[2] = 0x79622d32
    state[3] = 0x6b206574

    i = 0
    while i < 8:
        state[4 + i] = load_u32_le(key, 4 * i)
        i += 1

    state[12] = counter & 0xFFFFFFFF
    state[13] = load_u32_le(nonce, 0)
    state[14] = load_u32_le(nonce, 4)
    state[15] = load_u32_le(nonce, 8)

    working = state.copy()
    round_index = 0
    while round_index < 10:
        # 列轮
        working[0], working[4], working[8], working[12] = chacha20_quarter_round(working[0], working[4], working[8], working[12])
        working[1], working[5], working[9], working[13] = chacha20_quarter_round(working[1], working[5], working[9], working[13])
        working[2], working[6], working[10], working[14] = chacha20_quarter_round(working[2], working[6], working[10], working[14])
        working[3], working[7], working[11], working[15] = chacha20_quarter_round(working[3], working[7], working[11], working[15])
        # 对角轮
        working[0], working[5], working[10], working[15] = chacha20_quarter_round(working[0], working[5], working[10], working[15])
        working[1], working[6], working[11], working[12] = chacha20_quarter_round(working[1], working[6], working[11], working[12])
        working[2], working[7], working[8], working[13] = chacha20_quarter_round(working[2], working[7], working[8], working[13])
        working[3], working[4], working[9], working[14] = chacha20_quarter_round(working[3], working[4], working[9], working[14])
        round_index += 1

    # 加原 state
    output_words = [0] * 16
    word_index = 0
    while word_index < 16:
        output_words[word_index] = (working[word_index] + state[word_index]) & 0xFFFFFFFF
        word_index += 1
    output_bytes = bytearray()
    word_index = 0
    while word_index < 16:
        output_bytes += pack_u32_le(output_words[word_index])
        word_index += 1
    return bytes(output_bytes)

def chacha20_xor(key: bytes, nonce: bytes, initial_counter: int, data: bytes) -> bytes:
    """
    用 ChaCha20 生成 keystream 与明文/密文异或，counter=1。
    """
    output = bytearray(len(data))
    counter = initial_counter & 0xFFFFFFFF
    offset = 0
    while offset < len(data):
        keystream = chacha20_block(key, counter, nonce)
        counter = (counter + 1) & 0xFFFFFFFF
        bytes_remaining = len(data) - offset
        block_bytes = CHACHA_BLOCK_SIZE
        if bytes_remaining < block_bytes:
            block_bytes = bytes_remaining
        i = 0
        while i < block_bytes:
            output[offset + i] = data[offset + i] ^ keystream[i]
            i += 1
        offset += block_bytes
    return bytes(output)

# ========================
# Poly1305/MAC相关
# ========================
def poly1305_one_time_key(key: bytes, nonce: bytes) -> bytes:
    """
    用 chacha20 生成本块分块唯一的 Poly1305 钥匙（取 counter=0 的前 32 字节）
    """
    block0 = chacha20_block(key, 0, nonce)
    return block0[0:32]

def poly1305_mac(message: bytes, one_time_key: bytes) -> bytes:
    """
    Poly1305 MAC 计算
    """
    if one_time_key is None or len(one_time_key) != 32:
        raise ValueError("Poly1305 one-time key must be 32 bytes.")
    r = int.from_bytes(one_time_key[0:16], "little")
    s = int.from_bytes(one_time_key[16:32], "little")
    r = r & 0x0ffffffc0ffffffc0ffffffc0fffffff
    p = (1 << 130) - 5
    acc = 0
    offset = 0
    while offset < len(message):
        block = message[offset:offset + 16]
        n = int.from_bytes(block, "little") + (1 << (8 * len(block)))
        acc = (acc + n) % p
        acc = (acc * r) % p
        offset += 16
    tag_int = (acc + s) & ((1 << 128) - 1)
    return tag_int.to_bytes(16, "little")

def aead_encrypt_rfc8439(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> Tuple[bytes, bytes]:
    """
    RFC8439 AEAD 加密和 MAC 计算，AAD 为空字符串
    """
    one_time_key = poly1305_one_time_key(key, nonce)
    ciphertext = chacha20_xor(key, nonce, 1, plaintext)
    mac_data = bytearray()
    mac_data += aad
    mac_data += pad16(len(aad))
    mac_data += ciphertext
    mac_data += pad16(len(ciphertext))
    mac_data += pack_u64_le(len(aad))
    mac_data += pack_u64_le(len(ciphertext))
    tag = poly1305_mac(bytes(mac_data), one_time_key)
    return ciphertext, tag

def aead_decrypt_rfc8439(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes) -> bytes:
    """
    RFC8439 AEAD 解密，先校验 tag 通过才输出明文
    """
    if tag is None or len(tag) != TAG_SIZE:
        raise ValueError("Tag must be 16 bytes.")
    one_time_key = poly1305_one_time_key(key, nonce)
    mac_data = bytearray()
    mac_data += aad
    mac_data += pad16(len(aad))
    mac_data += ciphertext
    mac_data += pad16(len(ciphertext))
    mac_data += pack_u64_le(len(aad))
    mac_data += pack_u64_le(len(ciphertext))
    expected_tag = poly1305_mac(bytes(mac_data), one_time_key)
    if not constant_time_equals(expected_tag, tag):
        raise ValueError("Authentication failed (wrong password or corrupted data).")
    plaintext = chacha20_xor(key, nonce, 1, ciphertext)
    return plaintext

# ========================
# 分块 nonce 派生
# ========================
def derive_record_nonce(base_nonce: bytes, record_index: int) -> bytes:
    """
    每个分块唯一 nonce 派生方式（base_nonce XOR (LE32(idx)+0*8)）
    """
    if base_nonce is None or len(base_nonce) != NONCE_SIZE:
        raise ValueError("Base nonce must be 12 bytes.")
    if record_index < 0 or record_index > 0xFFFFFFFF:
        raise ValueError("Record index out of range (uint32).")
    mask = struct.pack("<I", record_index) + (b"\x00" * 8)
    output = bytearray(NONCE_SIZE)
    i = 0
    while i < NONCE_SIZE:
        output[i] = base_nonce[i] ^ mask[i]
        i += 1
    return bytes(output)

# ========================
# Header 结构体
# ========================
@dataclass(frozen=True)
class HeaderV3:
    flags: int
    chunk_size: int
    base_nonce: bytes
    kdf_id: int
    pbkdf2_iterations: int
    salt: bytes

# ========== header 写入与读取 =============
def read_exact(file_obj, size: int) -> bytes:
    """
    固定长度安全读取（不足直接认为截断）
    """
    data = file_obj.read(size)
    if len(data) != size:
        raise ValueError("Truncated file.")
    return data

def write_header_v3_password(file_obj, chunk_size: int, base_nonce: bytes, pbkdf2_iterations: int, salt: bytes) -> None:
    """
    写 CC20P13C 容器头部，存储密钥派生和参数
    """
    if len(base_nonce) != NONCE_SIZE:
        raise ValueError("base_nonce length invalid.")
    if len(salt) != DEFAULT_SALT_LENGTH:
        raise ValueError("salt length invalid.")
    if pbkdf2_iterations <= 0 or pbkdf2_iterations > 0xFFFFFFFF:
        raise ValueError("pbkdf2_iterations out of range.")
    flags = FLAG_PASSWORD_KDF
    file_obj.write(MAGIC)
    file_obj.write(struct.pack("B", VERSION))
    file_obj.write(struct.pack("B", flags))
    file_obj.write(struct.pack("<I", chunk_size))
    file_obj.write(base_nonce)
    file_obj.write(struct.pack("B", KDF_ID_PBKDF2_SHA256))
    file_obj.write(struct.pack("<I", pbkdf2_iterations))
    file_obj.write(struct.pack("B", len(salt)))
    file_obj.write(salt)

def read_header_v3_password(file_obj) -> HeaderV3:
    """
    严格读取并解析 header，校验所有参数正确
    """
    magic = read_exact(file_obj, 8)
    if magic != MAGIC:
        raise ValueError("Bad magic (not a CC20P13C file).")
    version = struct.unpack("B", read_exact(file_obj, 1))[0]
    if version != VERSION:
        raise ValueError("Unsupported version: %d" % version)
    flags = struct.unpack("B", read_exact(file_obj, 1))[0]
    chunk_size = struct.unpack("<I", read_exact(file_obj, 4))[0]
    base_nonce = read_exact(file_obj, NONCE_SIZE)
    if (flags & FLAG_PASSWORD_KDF) == 0:
        raise ValueError("This tool expects password-KDF files, but flag is not set.")
    kdf_id = struct.unpack("B", read_exact(file_obj, 1))[0]
    if kdf_id != KDF_ID_PBKDF2_SHA256:
        raise ValueError("Unsupported KDF id: %d" % kdf_id)
    pbkdf2_iterations = struct.unpack("<I", read_exact(file_obj, 4))[0]
    salt_len = struct.unpack("B", read_exact(file_obj, 1))[0]
    if salt_len != DEFAULT_SALT_LENGTH:
        raise ValueError("Unsupported salt length: %d" % salt_len)
    salt = read_exact(file_obj, salt_len)
    header = HeaderV3(
        flags=flags,
        chunk_size=chunk_size,
        base_nonce=base_nonce,
        kdf_id=kdf_id,
        pbkdf2_iterations=pbkdf2_iterations,
        salt=salt
    )
    return header

# ========================
# 文件加密与解密（单文件）
# ========================
def encrypt_file_password(
    input_file_path: str,
    output_file_path: str,
    password: str,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    pbkdf2_iterations: int = DEFAULT_PBKDF2_ITERATIONS
) -> None:
    """
    对单个文件流式加密，分块处理，输出符合规范的 .cc20p13c 容器文件
    """
    aad = b""
    base_nonce = os.urandom(NONCE_SIZE)
    salt = os.urandom(DEFAULT_SALT_LENGTH)
    key = derive_key_from_password(password, salt, pbkdf2_iterations)
    ensure_parent_directory(output_file_path)
    with open(input_file_path, "rb") as input_file:
        with open(output_file_path, "wb") as output_file:
            write_header_v3_password(output_file, chunk_size, base_nonce, pbkdf2_iterations, salt)
            record_index = 0
            while True:
                plaintext_chunk = input_file.read(chunk_size)
                if plaintext_chunk == b"":
                    break
                record_nonce = derive_record_nonce(base_nonce, record_index)
                ciphertext_chunk, tag = aead_encrypt_rfc8439(key, record_nonce, plaintext_chunk, aad)
                output_file.write(struct.pack("<I", len(plaintext_chunk)))
                output_file.write(ciphertext_chunk)
                output_file.write(tag)
                record_index = (record_index + 1) & 0xFFFFFFFF

def decrypt_file_password(input_file_path: str, output_file_path: str, password: str) -> None:
    """
    对单文件解密（解密到临时文件，全部ok后原子rename，异常时不留空文件）
    """
    aad = b""
    tmp_dir = os.path.dirname(os.path.abspath(output_file_path))
    with open(input_file_path, "rb") as input_file:
        with tempfile.NamedTemporaryFile(dir=tmp_dir, delete=False) as tmp_output_file:
            tmp_path = tmp_output_file.name
            try:
                header = read_header_v3_password(input_file)
                key = derive_key_from_password(password, header.salt, header.pbkdf2_iterations)
                record_index = 0
                while True:
                    length_bytes = input_file.read(4)
                    if len(length_bytes) == 0:
                        break
                    if len(length_bytes) != 4:
                        raise ValueError("Truncated file (record length).")
                    plaintext_len = struct.unpack("<I", length_bytes)[0]
                    if plaintext_len == 0:
                        raise ValueError("Invalid record length: 0")
                    if plaintext_len > header.chunk_size:
                        raise ValueError("Invalid record length (exceeds chunk_size).")
                    ciphertext = input_file.read(plaintext_len)
                    if len(ciphertext) != plaintext_len:
                        raise ValueError("Truncated file (ciphertext).")
                    tag = input_file.read(TAG_SIZE)
                    if len(tag) != TAG_SIZE:
                        raise ValueError("Truncated file (tag).")
                    record_nonce = derive_record_nonce(header.base_nonce, record_index)
                    plaintext = aead_decrypt_rfc8439(key, record_nonce, ciphertext, tag, aad)
                    tmp_output_file.write(plaintext)
                    record_index = (record_index + 1) & 0xFFFFFFFF
                tmp_output_file.flush()
                os.fsync(tmp_output_file.fileno())
            except Exception as e:
                tmp_output_file.close()
                os.remove(tmp_path)
                raise
    ensure_parent_directory(output_file_path)
    shutil.move(tmp_path, output_file_path)

# ========================
# 多线程目录递归加密/解密
# ========================
def encrypt_path_password(
    source_path: str,
    output_directory: str,
    password: str,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    pbkdf2_iterations: int = DEFAULT_PBKDF2_ITERATIONS,
    max_workers: int = 4
) -> None:
    """
    多线程递归加密整个目录（单文件情形仍顺序执行，目录则并发每个文件）
    """
    source_path = os.path.abspath(source_path)
    output_directory = os.path.abspath(output_directory)
    os.makedirs(output_directory, exist_ok=True)
    file_tasks = []
    # 单文件直接加密
    if os.path.isfile(source_path):
        output_file_path = os.path.join(output_directory, os.path.basename(source_path) + ".cc20p13c")
        encrypt_file_password(source_path, output_file_path, password, chunk_size, pbkdf2_iterations)
        return
    if not os.path.isdir(source_path):
        raise ValueError("Source not found: %s" % source_path)
    # 收集所有任务（待加密文件）
    for root, directory_names, file_names in os.walk(source_path):
        for file_name in file_names:
            input_file_path = os.path.join(root, file_name)
            if not os.path.isfile(input_file_path):
                continue
            relative_path = os.path.relpath(input_file_path, source_path)
            output_file_path = os.path.join(output_directory, relative_path + ".cc20p13c")
            file_tasks.append((input_file_path, output_file_path))
    def worker(args):
        src, dst = args
        encrypt_file_password(src, dst, password, chunk_size, pbkdf2_iterations)
    # 多线程并发，最大 max_workers
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        fs = [pool.submit(worker, task) for task in file_tasks]
        for f in as_completed(fs):
            try:
                f.result()
            except Exception as e:
                print(f"ERROR in encrypt: {e}")

def decrypt_path_password(
    source_path: str,
    output_directory: str,
    password: str,
    strip_suffix: str = ".cc20p13c",
    max_workers: int = 4
) -> None:
    """
    多线程递归解密整个目录，自动剥离后缀，任务失败不产生半成品文件
    """
    source_path = os.path.abspath(source_path)
    output_directory = os.path.abspath(output_directory)
    os.makedirs(output_directory, exist_ok=True)
    file_tasks = []
    # 单文件直接解密
    if os.path.isfile(source_path):
        base_name = os.path.basename(source_path)
        if base_name.lower().endswith(strip_suffix):
            output_name = base_name[:-len(strip_suffix)]
        else:
            output_name = base_name + ".dec"
        output_file_path = os.path.join(output_directory, output_name)
        decrypt_file_password(source_path, output_file_path, password)
        return
    if not os.path.isdir(source_path):
        raise ValueError("Source not found: %s" % source_path)
    # 收集待解密文件
    for root, directory_names, file_names in os.walk(source_path):
        for file_name in file_names:
            if not file_name.lower().endswith(strip_suffix):
                continue
            input_file_path = os.path.join(root, file_name)
            if not os.path.isfile(input_file_path):
                continue
            relative_path = os.path.relpath(input_file_path, source_path)
            if relative_path.lower().endswith(strip_suffix):
                relative_output_path = relative_path[:-len(strip_suffix)]
            else:
                relative_output_path = relative_path + ".dec"
            output_file_path = os.path.join(output_directory, relative_output_path)
            file_tasks.append((input_file_path, output_file_path))
    def worker(args):
        src, dst = args
        decrypt_file_password(src, dst, password)
    # 多线程并发，最大 max_workers
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        fs = [pool.submit(worker, task) for task in file_tasks]
        for f in as_completed(fs):
            try:
                f.result()
            except Exception as e:
                print(f"ERROR in decrypt: {e}")

# ========================
# 控制台 CLI
# ========================
def prompt_path(prompt_text: str) -> str:
    """
    路径输入，兼容带引号（方便 windows）
    """
    value = input(prompt_text)
    value = value.strip()
    value = value.strip('"')
    return value

def is_subpath(parent_path: str, candidate_path: str) -> bool:
    """
    判断 candidate_path 是否在 parent_path 内部（防止递归误操作）
    """
    parent_abs = os.path.abspath(parent_path)
    candidate_abs = os.path.abspath(candidate_path)
    try:
        common = os.path.commonpath([parent_abs, candidate_abs])
    except ValueError:
        return False
    return common == parent_abs

def main() -> None:
    """
    主入口（交互，防呆，调用多线程递归接口）
    """
    print("CC20P13C (ChaCha20-Poly1305) Interactive Tool")
    print("Choose mode: Encrypt(E) or Decrypt(D)")
    mode = input("Mode (E/D): ").strip().lower()
    if mode != "e" and mode != "d":
        print("Invalid mode.")
        return
    password = getpass.getpass("Password: ")
    if password == "":
        print("Empty password is not allowed.")
        return
    if mode == "e":
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("Passwords do not match.")
            return
    source_path = prompt_path("Source path (file or directory): ")
    if not os.path.exists(source_path):
        print("Source does not exist.")
        return
    output_directory = prompt_path("Output directory: ")
    if output_directory == "":
        print("Output directory is required.")
        return
    source_abs = os.path.abspath(source_path)
    output_abs = os.path.abspath(output_directory)
    # 防止输出目录放源文件夹内
    if os.path.isdir(source_abs):
        if is_subpath(source_abs, output_abs):
            print("Refusing to run because output directory is inside source directory.")
            print("Source: %s" % source_abs)
            print("Output: %s" % output_abs)
            return
    try:
        max_workers = os.cpu_count() or 4    # 默认为所有CPU核心
        if mode == "e":
            encrypt_path_password(source_abs, output_abs, password, max_workers=max_workers)
            print("Encryption complete.")
        else:
            decrypt_path_password(source_abs, output_abs, password, max_workers=max_workers)
            print("Decryption complete.")
    except Exception as exc:
        print("ERROR: %s" % str(exc))

if __name__ == "__main__":
    main()
