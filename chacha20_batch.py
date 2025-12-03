#!/usr/bin/env python3
"""
交互式批量 ChaCha20-Poly1305 加密/解密（基于 PyCryptodome）
行为要点保持不变：
- 加密输出文件与原文件同名（写入指定输出目录），不添加后缀。
- 从用户输入密码通过 PBKDF2-HMAC-SHA256 派生 32 字节密钥。
  盐保存在 chacha20_key.salt（存在则重用，不存在则生成并写入）。
- 每个加密文件使用随机 12 字节 nonce；输出文件布局： nonce(12) || tag(16) || ciphertext
- 解密时验证 Poly1305 tag；验证失败时不写输出文件并报告错误。
- 并发处理文件（线程池），并对每个文件使用临时文件写入后替换目标，避免不完整写入。
- 交互式：提示用户输入密码、选择模式（encrypt/decrypt）、输入/输出目录、并发线程数。

风格限制：
- 不使用嵌套表达式或较深嵌套结构（保持平坦结构）。
- 不使用列表/字典/集合推导式。
- 其他逻辑不修改。
"""
from pathlib import Path
import getpass
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
# ---- 配置常量 ----
KEY_LEN = 32
NONCE_SIZE = 12
TAG_SIZE = 16
DEFAULT_THREADS = 8
KEYFILE_SALT = "chacha20_key.salt"
KDF_ITERS = 200_000
# ---- 类型 ----
Result = Tuple[str, str, str]
def derive_key_from_password(password: str, salt_path: str = KEYFILE_SALT) -> bytes:
    salt_file = Path(salt_path)
    if salt_file.exists():
        data = salt_file.read_bytes()
        salt = data
    else:
        salt = get_random_bytes(16)
        salt_file.write_bytes(salt)
    key = PBKDF2(password, salt, dkLen=KEY_LEN, count=KDF_ITERS, hmac_hash_module=SHA256)
    return key
def encrypt_file(in_path: str, out_path: str, key: bytes) -> Result:
    try:
        inp = Path(in_path)
        outp = Path(out_path)
        plaintext = inp.read_bytes()
        nonce = get_random_bytes(NONCE_SIZE)
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        tmp = outp.with_suffix(outp.suffix + ".tmp")
        f = tmp.open("wb")
        try:
            f.write(nonce)
            f.write(tag)
            f.write(ciphertext)
        finally:
            f.close()
        tmp.replace(outp)
        return (str(inp), str(outp), "ok")
    except Exception as e:
        return (str(in_path), str(out_path), "error: " + str(e))
def decrypt_file(in_path: str, out_path: str, key: bytes) -> Result:
    try:
        inp = Path(in_path)
        outp = Path(out_path)
        data = inp.read_bytes()
        if len(data) < NONCE_SIZE + TAG_SIZE:
            return (str(inp), str(outp), "error: input too short for nonce+tag")
        nonce = data[0:NONCE_SIZE]
        tag = data[NONCE_SIZE:NONCE_SIZE + TAG_SIZE]
        ciphertext = data[NONCE_SIZE + TAG_SIZE:]
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        try:
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError:
            return (str(inp), str(outp), "error: authentication failed")
        tmp = outp.with_suffix(outp.suffix + ".tmp")
        f = tmp.open("wb")
        try:
            f.write(plaintext)
        finally:
            f.close()
        tmp.replace(outp)
        return (str(inp), str(outp), "ok")
    except Exception as e:
        return (str(in_path), str(out_path), "error: " + str(e))
def process_batch(input_dir: str, output_dir: str, key: bytes, mode: str = "encrypt", threads: int = DEFAULT_THREADS) -> List[Result]:
    input_path = Path(input_dir)
    output_path = Path(output_dir)
    if not input_path.exists() or not input_path.is_dir():
        raise ValueError("输入目录不存在或不是目录")
    output_path.mkdir(parents=True, exist_ok=True)
    tasks = []
    it = input_path.iterdir()
    for p in it:
        if not p.is_file():
            continue
        dest = output_path / p.name
        if mode == "encrypt":
            tasks.append((encrypt_file, str(p), str(dest)))
        else:
            tasks.append((decrypt_file, str(p), str(dest)))
    results = []
    if len(tasks) == 0:
        return results
    max_workers = DEFAULT_THREADS
    try:
        max_workers = int(threads)
    except Exception:
        max_workers = DEFAULT_THREADS
    if max_workers < 1:
        max_workers = 1
    ex = ThreadPoolExecutor(max_workers=max_workers)
    try:
        future_to_task = {}
        for task in tasks:
            func = task[0]
            inp = task[1]
            out = task[2]
            future = ex.submit(func, inp, out, key)
            future_to_task[future] = (inp, out)
        completed = as_completed(list(future_to_task.keys()))
        for fut in completed:
            pair = future_to_task[fut]
            inp = pair[0]
            out = pair[1]
            try:
                res = fut.result()
                results.append(res)
            except Exception as e:
                results.append((inp, out, "error: " + str(e)))
    finally:
        ex.shutdown(wait=True)
    return results
def main():
    print("ChaCha20-Poly1305 批量加/解密（输出文件与原名相同）")
    password = getpass.getpass("请输入密码（用于派生密钥）：")
    if not password:
        print("密码不能为空，退出")
        return
    key = derive_key_from_password(password)
    while True:
        mode = input("选择模式（encrypt/decrypt）：").strip().lower()
        if mode == "encrypt" or mode == "decrypt":
            break
        print("请输入 'encrypt' 或 'decrypt'")
    input_dir = input("输入要处理的目录路径：").strip()
    output_dir = input("输出目录（将创建/覆盖同名文件）路径：").strip()
    threads = DEFAULT_THREADS
    t_in = input(f"并发线程数（默认 {DEFAULT_THREADS}）：").strip()
    if t_in != "":
        try:
            threads_val = int(t_in)
            if threads_val >= 1:
                threads = threads_val
            else:
                print("线程数必须 >= 1，使用默认值")
        except Exception:
            threads = DEFAULT_THREADS
    try:
        results = process_batch(input_dir, output_dir, key, mode=mode, threads=threads)
    except Exception as e:
        print("批处理失败: " + str(e))
        return
    ok_count = 0
    errors = []
    for r in results:
        if r[2] == "ok":
            ok_count = ok_count + 1
        else:
            errors.append(r)
    print("完成。成功: " + str(ok_count) + "，失败: " + str(len(errors)))
    if len(errors) > 0:
        print("失败明细：")
        for r in errors:
            print("- " + r[0] + " -> " + r[1] + " : " + r[2])
if __name__ == "__main__":
    main()
