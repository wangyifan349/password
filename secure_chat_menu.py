#!/usr/bin/env python3
"""
secure_chat_menu.py
- Menu-driven CLI (text menu) to run as server or client
- End-to-end encryption: X25519 + Ed25519 + HKDF-SHA256 + ChaCha20-Poly1305
- Threads: "sender-thread" and "receiver-thread"
- Support chat and file transfer (/sendfile <path>)
- No command-line args required; menu interactions drive behavior
"""
import socket, struct, threading, os, sys, json
from pathlib import Path
from queue import Queue, Empty
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
# framing helpers
def send_frame(sock, data):
    sock.sendall(struct.pack("!I", len(data)) + data)
def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("closed")
        buf += chunk
    return buf
def recv_frame(sock):
    hdr = recv_exact(sock, 4)
    (length,) = struct.unpack("!I", hdr)
    if length == 0:
        return b""
    return recv_exact(sock, length)
# key helpers
def x_pub_bytes(pub): return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
def ed_pub_bytes(pub): return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
# handshake: exchange JSON {x_pub, ed_pub, x_sig, salt}
def handshake(sock, is_server):
    x_priv = x25519.X25519PrivateKey.generate()
    x_pub = x_pub_bytes(x_priv.public_key())
    ed_priv = ed25519.Ed25519PrivateKey.generate()
    ed_pub = ed_pub_bytes(ed_priv.public_key())
    x_sig = ed_priv.sign(x_pub)
    salt = os.urandom(32) if is_server else None
    out = {"x_pub": x_pub.hex(), "ed_pub": ed_pub.hex(), "x_sig": x_sig.hex(), "salt": salt.hex() if salt else None}
    send_frame(sock, json.dumps(out).encode())
    peer_raw = recv_frame(sock)
    peer = json.loads(peer_raw.decode())
    peer_x = bytes.fromhex(peer["x_pub"])
    peer_ed = bytes.fromhex(peer["ed_pub"])
    peer_sig = bytes.fromhex(peer["x_sig"])
    peer_salt = peer.get("salt")
    if not salt:
        salt = bytes.fromhex(peer_salt) if peer_salt else os.urandom(32)
    ed25519.Ed25519PublicKey.from_public_bytes(peer_ed).verify(peer_sig, peer_x)
    shared = x_priv.exchange(x25519.X25519PublicKey.from_public_bytes(peer_x))
    key = HKDF(hashes.SHA256(), length=32, salt=salt, info=b"handshake v1").derive(shared)
    return ChaCha20Poly1305(key), key, salt
# pack / unpack plaintext: 4-byte header length + header(json) + body
def pack(header, body=b""):
    hb = json.dumps(header).encode()
    return struct.pack("!I", len(hb)) + hb + body
def unpack(pt):
    hlen = struct.unpack("!I", pt[:4])[0]
    header = json.loads(pt[4:4+hlen].decode())
    body = pt[4+hlen:]
    return header, body
# Sender thread: consumes send_queue; also reads stdin non-blocking via main thread command input
def sender(sock, aead, send_queue, stop_event):
    threading.current_thread().name = "sender-thread"
    aad = b"session"
    while not stop_event.is_set():
        try:
            item = send_queue.get(timeout=0.2)
        except Empty:
            continue
        if item is None:
            break
        typ = item.get("type")
        if typ == "MSG":
            nonce = os.urandom(12)
            send_frame(sock, nonce + aead.encrypt(nonce, pack({"type":"MSG"}, item["text"].encode()), aad))
        elif typ == "SEND_FILE":
            path = item["path"]
            p = Path(path)
            if not p.exists() or not p.is_file():
                print("file not found:", path)
                continue
            fname = p.name
            size = p.stat().st_size
            nonce = os.urandom(12)
            send_frame(sock, nonce + aead.encrypt(nonce, pack({"type":"FILE_START","filename":fname,"size":size}), aad))
            with p.open("rb") as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk: break
                    nonce = os.urandom(12)
                    send_frame(sock, nonce + aead.encrypt(nonce, pack({"type":"FILE_CHUNK"}, chunk), aad))
            nonce = os.urandom(12)
            send_frame(sock, nonce + aead.encrypt(nonce, pack({"type":"FILE_END","filename":fname}), aad))
            print("sent file:", fname)
        elif typ == "CLOSE":
            nonce = os.urandom(12)
            send_frame(sock, nonce + aead.encrypt(nonce, pack({"type":"CLOSE"}), aad))
            break
    try:
        sock.shutdown(socket.SHUT_WR)
    except Exception:
        pass
# Receiver thread: writes incoming messages to console and saves files to download_dir
def receiver(sock, aead, download_dir, stop_event):
    threading.current_thread().name = "receiver-thread"
    aad = b"session"
    file_bufs = {}
    last_file = None
    while not stop_event.is_set():
        try:
            frame = recv_frame(sock)
        except ConnectionError:
            print("connection closed by peer")
            break
        if not frame:
            continue
        if len(frame) < 12:
            print("bad frame")
            continue
        nonce, cipher = frame[:12], frame[12:]
        try:
            pt = aead.decrypt(nonce, cipher, aad)
        except Exception:
            print("decrypt fail")
            continue
        header, body = unpack(pt)
        t = header.get("type")
        if t == "MSG":
            print("[peer]", body.decode())
        elif t == "FILE_START":
            fname = header.get("filename","unnamed")
            file_bufs[fname] = bytearray()
            last_file = fname
            print("[peer] sending", fname, "size", header.get("size"))
        elif t == "FILE_CHUNK":
            if last_file is None:
                print("unexpected file chunk")
                continue
            file_bufs[last_file].extend(body)
        elif t == "FILE_END":
            fname = header.get("filename")
            if not fname or fname not in file_bufs:
                print("file end unknown")
                continue
            dest = Path(download_dir)/fname
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(file_bufs[fname])
            print("[peer] received file", dest, len(file_bufs[fname]), "bytes")
            del file_bufs[fname]
            last_file = None
        elif t == "CLOSE":
            print("peer requested close")
            break
        else:
            print("unknown type", t)
    stop_event.set()
    try:
        sock.shutdown(socket.SHUT_RD)
    except Exception:
        pass
# Interactive session loop: main thread reads stdin and queues sends
def interactive_session(conn, send_queue, stop_event):
    """
    主线程会话循环：读取 stdin 命令或消息并推入 send_queue。
    命令：
      /sendfile <path>   - 发送文件
      /quit              - 关闭会话并返回菜单
    Ctrl-D/Ctrl-C 会像 /quit 一样处理。
    """
    try:
        while not stop_event.is_set():
            try:
                line = input()
            except (EOFError, KeyboardInterrupt):
                line = "/quit"
            line = line.strip()
            if not line:
                continue
            if line.startswith("/sendfile "):
                path = line[len("/sendfile "):].strip()
                if path:
                    send_queue.put({"type":"SEND_FILE", "path": path})
                else:
                    print("usage: /sendfile <path>")
            elif line == "/quit":
                send_queue.put({"type":"CLOSE"})
                # ensure sender unblocks if waiting
                send_queue.put(None)
                stop_event.set()
                break
            else:
                send_queue.put({"type":"MSG","text": line})
    finally:
        return
# Menu helpers
def prompt(text):
    try:
        return input(text)
    except (EOFError, KeyboardInterrupt):
        return ""
def run_menu():
    send_queue = Queue()
    conn = None
    recv_t = None
    send_t = None
    stop_event = threading.Event()
    download_dir = "downloads"
    while True:
        print("\n=== Secure Chat Menu ===")
        print("1) Start server")
        print("2) Connect to server")
        print("3) Send message (use in-session)")
        print("4) Send file (use /sendfile in-session)")
        print("5) Disconnect (use in-session /quit)")
        print("6) Quit")
        choice = prompt("Choose: ").strip()
        if choice == "1":
            if conn:
                print("Already connected")
                continue
            host = prompt("Bind host (default 0.0.0.0): ").strip() or "0.0.0.0"
            port = int(prompt("Bind port (default 9000): ").strip() or "9000")
            s = socket.socket()
            s.bind((host, port))
            s.listen(1)
            print("Listening", host, port)
            conn, addr = s.accept()
            print("Accepted", addr)
            aead, key, salt = handshake(conn, True)
            stop_event.clear()
            recv_t = threading.Thread(target=receiver, args=(conn, aead, download_dir, stop_event))
            send_t = threading.Thread(target=sender, args=(conn, aead, send_queue, stop_event))
            recv_t.start(); send_t.start()
            # Enter interactive session (blocks until /quit or peer close)
            interactive_session(conn, send_queue, stop_event)
            # cleanup after session
            stop_event.set()
            send_queue.put(None)
            if send_t: send_t.join()
            if recv_t: recv_t.join()
            try: conn.close()
            except Exception: pass
            conn = None
            print("Session closed")
        elif choice == "2":
            if conn:
                print("Already connected")
                continue
            host = prompt("Server host (default 127.0.0.1): ").strip() or "127.0.0.1"
            port = int(prompt("Server port (default 9000): ").strip() or "9000")
            conn = socket.socket()
            conn.connect((host, port))
            aead, key, salt = handshake(conn, False)
            stop_event.clear()
            recv_t = threading.Thread(target=receiver, args=(conn, aead, download_dir, stop_event))
            send_t = threading.Thread(target=sender, args=(conn, aead, send_queue, stop_event))
            recv_t.start(); send_t.start()
            print("Connected")
            # Enter interactive session (blocks until /quit or peer close)
            interactive_session(conn, send_queue, stop_event)
            # cleanup after session
            stop_event.set()
            send_queue.put(None)
            if send_t: send_t.join()
            if recv_t: recv_t.join()
            try: conn.close()
            except Exception: pass
            conn = None
            print("Session closed")
        elif choice == "3":
            print("Use the session input to send messages. Start or connect first.")
        elif choice == "4":
            print("Use /sendfile <path> while in-session to send a file.")
        elif choice == "5":
            if not conn:
                print("Not connected")
                continue
            # emulate in-session quit
            send_queue.put({"type":"CLOSE"})
            stop_event.set()
            send_queue.put(None)
            if send_t: send_t.join()
            if recv_t: recv_t.join()
            try: conn.close()
            except Exception: pass
            conn = None
            print("Disconnected")
        elif choice == "6":
            if conn:
                send_queue.put({"type":"CLOSE"})
                stop_event.set()
                send_queue.put(None)
                if send_t: send_t.join()
                if recv_t: recv_t.join()
                try: conn.close()
                except Exception: pass
            print("Bye")
            break
        else:
            print("Invalid choice")
if __name__ == "__main__":
    run_menu()
