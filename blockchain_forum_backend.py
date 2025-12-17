import sqlite3
import hashlib
import nacl.signing
import base64
import time
from flask import Flask, request, jsonify, Response
import json
DB_PATH = "forum.db"
SIGNATURE_VALID_WINDOW = 300  # 签名时间窗口（秒）
app = Flask(__name__)
# ========= 工具函数 =========
def sha256(data):
    return hashlib.sha256(data).hexdigest()
def b64decode(text):
    return base64.b64decode(text)
def verify_signature(public_key_b64, signature_b64, message_bytes):
    try:
        verify_key = nacl.signing.VerifyKey(b64decode(public_key_b64))
        signature = b64decode(signature_b64)
        verify_key.verify(message_bytes, signature)
        return True
    except Exception:
        return False
def address_from_public_key(public_key_b64):
    return sha256(b64decode(public_key_b64))
def calculate_post_block_hash(
    title,
    content,
    address,
    public_key_b64,
    signature_b64,
    timestamp,
    prev_hash
):
    raw_data = (
        title + "\n"
        + content + "\n"
        + address + "\n"
        + str(timestamp) + "\n"
        + public_key_b64 + "\n"
        + signature_b64 + "\n"
        + prev_hash
    ).encode("utf-8")
    return sha256(raw_data)
def calculate_comment_block_hash(
    post_id,
    content,
    address,
    public_key_b64,
    signature_b64,
    timestamp,
    prev_hash
):
    raw_data = (
        str(post_id) + "\n"
        + content + "\n"
        + address + "\n"
        + str(timestamp) + "\n"
        + public_key_b64 + "\n"
        + signature_b64 + "\n"
        + prev_hash
    ).encode("utf-8")
    return sha256(raw_data)
# ========= 数据库函数 =========
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        content TEXT NOT NULL,
        address TEXT NOT NULL,
        public_key_b64 TEXT NOT NULL,
        signature_b64 TEXT NOT NULL,
        timestamp INTEGER NOT NULL,
        block_hash TEXT NOT NULL,
        prev_hash TEXT NOT NULL
    )
    """)
    c.execute("""
    CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        post_id INTEGER NOT NULL,
        content TEXT NOT NULL,
        address TEXT NOT NULL,
        public_key_b64 TEXT NOT NULL,
        signature_b64 TEXT NOT NULL,
        timestamp INTEGER NOT NULL,
        block_hash TEXT NOT NULL,
        prev_hash TEXT NOT NULL,
        FOREIGN KEY (post_id) REFERENCES posts(id)
    )
    """)
    conn.commit()
    conn.close()
def get_last_post_hash():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT block_hash FROM posts ORDER BY id DESC LIMIT 1")
    row = c.fetchone()
    conn.close()
    return row[0] if row else "GENESIS"
def get_last_comment_hash(post_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT block_hash FROM comments WHERE post_id = ? ORDER BY id DESC LIMIT 1", (post_id,))
    row = c.fetchone()
    conn.close()
    return row[0] if row else "GENESIS"
def insert_post(title, content, public_key_b64, signature_b64, timestamp):
    message = (title + "\n" + content + "\n" + str(timestamp)).encode("utf-8")
    if not verify_signature(public_key_b64, signature_b64, message):
        return False, "invalid signature"
    now = int(time.time())
    if abs(now - int(timestamp)) > SIGNATURE_VALID_WINDOW:
        return False, "timestamp out of valid window"
    address = address_from_public_key(public_key_b64)
    prev_hash = get_last_post_hash()
    block_hash = calculate_post_block_hash(
        title, content, address, public_key_b64, signature_b64, timestamp, prev_hash
    )
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
    INSERT INTO posts (title, content, address, public_key_b64, signature_b64, timestamp, block_hash, prev_hash)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (title, content, address, public_key_b64, signature_b64, timestamp, block_hash, prev_hash)
    )
    conn.commit()
    post_id = c.lastrowid
    conn.close()
    return True, post_id
def insert_comment(post_id, content, public_key_b64, signature_b64, timestamp):
    message = ("COMMENT\n" + str(post_id) + "\n" + content + "\n" + str(timestamp)).encode("utf-8")
    if not verify_signature(public_key_b64, signature_b64, message):
        return False, "invalid signature"
    now = int(time.time())
    if abs(now - int(timestamp)) > SIGNATURE_VALID_WINDOW:
        return False, "timestamp out of valid window"
    address = address_from_public_key(public_key_b64)
    prev_hash = get_last_comment_hash(post_id)
    block_hash = calculate_comment_block_hash(
        post_id, content, address, public_key_b64, signature_b64, timestamp, prev_hash
    )
    # 检查post_id是否存在
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id FROM posts WHERE id = ?", (post_id,))
    if not c.fetchone():
        conn.close()
        return False, "post not found"
    c.execute("""
    INSERT INTO comments (post_id, content, address, public_key_b64, signature_b64, timestamp, block_hash, prev_hash)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (post_id, content, address, public_key_b64, signature_b64, timestamp, block_hash, prev_hash)
    )
    conn.commit()
    comment_id = c.lastrowid
    conn.close()
    return True, comment_id
def list_posts():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM posts ORDER BY timestamp DESC")
    rows = c.fetchall()
    results = []
    for row in rows:
        result = dict(row)
        c2 = conn.cursor()
        c2.execute("SELECT COUNT(*) FROM comments WHERE post_id = ?", (row["id"],))
        result["comments_count"] = c2.fetchone()[0]
        results.append(result)
    conn.close()
    return results
def get_post_with_comments(post_id):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM posts WHERE id = ?", (post_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        return None
    post = dict(row)
    c.execute("SELECT * FROM comments WHERE post_id = ? ORDER BY timestamp ASC", (post_id,))
    comments = [dict(r) for r in c.fetchall()]
    post["comments"] = comments
    conn.close()
    return post

def export_posts_all():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM posts ORDER BY id ASC")
    rows = c.fetchall()
    conn.close()
    return [dict(row) for row in rows]
def export_comments_all():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM comments ORDER BY id ASC")
    rows = c.fetchall()
    conn.close()
    return [dict(row) for row in rows]
# ========= API接口 =========
@app.route("/api/posts", methods=["POST"])
def api_create_post():
    post_data = request.get_json(force=True)
    title = post_data.get("title", "").strip()
    content = post_data.get("content", "").strip()
    public_key_b64 = post_data.get("public_key_b64")
    signature_b64 = post_data.get("signature_b64")
    timestamp = post_data.get("timestamp")
    if not title or not content or not public_key_b64 or not signature_b64 or timestamp is None:
        return jsonify({"error": "missing fields"}), 400
    try:
        timestamp = int(timestamp)
    except Exception:
        return jsonify({"error": "invalid timestamp"}), 400
    ret, result = insert_post(title, content, public_key_b64, signature_b64, timestamp)
    if not ret:
        return jsonify({"error": result}), 400
    return jsonify({"status": "ok", "post_id": result}), 201
@app.route("/api/posts/<int:post_id>/comment", methods=["POST"])
def api_create_comment(post_id):
    comment_data = request.get_json(force=True)
    content = comment_data.get("content", "").strip()
    public_key_b64 = comment_data.get("public_key_b64")
    signature_b64 = comment_data.get("signature_b64")
    timestamp = comment_data.get("timestamp")
    if not content or not public_key_b64 or not signature_b64 or timestamp is None:
        return jsonify({"error": "missing fields"}), 400
    try:
        timestamp = int(timestamp)
    except Exception:
        return jsonify({"error": "invalid timestamp"}), 400
    ret, result = insert_comment(post_id, content, public_key_b64, signature_b64, timestamp)
    if not ret:
        code = 404 if result == "post not found" else 400
        return jsonify({"error": result}), code
    return jsonify({"status": "ok", "comment_id": result}), 201
@app.route("/api/posts", methods=["GET"])
def api_list_posts():
    posts = list_posts()
    for post in posts:
        post.pop("public_key_b64")
        post.pop("signature_b64")
    return jsonify(posts)
@app.route("/api/posts/<int:post_id>", methods=["GET"])
def api_get_post(post_id):
    post = get_post_with_comments(post_id)
    if not post:
        return jsonify({"error": "not found"}), 404
    for comment in post["comments"]:
        comment.pop("public_key_b64")
        comment.pop("signature_b64")
    post.pop("public_key_b64")
    post.pop("signature_b64")
    return jsonify(post)
@app.route("/export/posts", methods=["GET"])
def api_export_posts():
    posts = export_posts_all()
    return Response(json.dumps(posts, indent=2, ensure_ascii=False), content_type="application/json")
@app.route("/export/comments", methods=["GET"])
def api_export_comments():
    comments = export_comments_all()
    return Response(json.dumps(comments, indent=2, ensure_ascii=False), content_type="application/json")

from flask import send_file
@app.route("/download/forum.db", methods=["GET"])
def download_db():
    return send_file(DB_PATH, as_attachment=True, download_name='forum.db', mimetype='application/octet-stream')
# ========= MAIN =========
if __name__ == "__main__":
    init_db()
    app.run(port=5000, debug=True)





import requests
import nacl.signing
import base64
import time
import random

BASE_URL = "http://127.0.0.1:5000"

# 生成 Ed25519 密钥对
signing_key = nacl.signing.SigningKey.generate()
verify_key = signing_key.verify_key
public_key_b64 = base64.b64encode(verify_key.encode()).decode("utf-8")

def sign_post(title, content, timestamp):
    msg = (title + "\n" + content + "\n" + str(timestamp)).encode("utf-8")
    signature = signing_key.sign(msg).signature
    sig_b64 = base64.b64encode(signature).decode("utf-8")
    return sig_b64

def sign_comment(post_id, content, timestamp):
    msg = ("COMMENT\n" + str(post_id) + "\n" + content + "\n" + str(timestamp)).encode("utf-8")
    signature = signing_key.sign(msg).signature
    sig_b64 = base64.b64encode(signature).decode("utf-8")
    return sig_b64

def test_create_post(title, content):
    timestamp = int(time.time())
    signature_b64 = sign_post(title, content, timestamp)
    data = {
        "title": title,
        "content": content,
        "public_key_b64": public_key_b64,
        "signature_b64": signature_b64,
        "timestamp": timestamp
    }
    r = requests.post(f"{BASE_URL}/api/posts", json=data)
    print("▶ 发帖:", r.status_code, r.json())
    return r

def test_create_comment(post_id, content):
    timestamp = int(time.time())
    signature_b64 = sign_comment(post_id, content, timestamp)
    data = {
        "content": content,
        "public_key_b64": public_key_b64,
        "signature_b64": signature_b64,
        "timestamp": timestamp
    }
    r = requests.post(f"{BASE_URL}/api/posts/{post_id}/comment", json=data)
    print("▶ 评论:", r.status_code, r.json())
    return r

def test_list_posts():
    r = requests.get(f"{BASE_URL}/api/posts")
    print("▶ 查询所有帖子:", r.status_code)
    print(r.json())
    return r

def test_get_post_with_comments(post_id):
    r = requests.get(f"{BASE_URL}/api/posts/{post_id}")
    print(f"▶ 查询帖子 {post_id}（含评论）:", r.status_code)
    print(r.json())
    return r

def test_error_cases():
    print("▶ [错误测试] 缺少字段")
    r = requests.post(f"{BASE_URL}/api/posts", json={})
    print(r.status_code, r.json())

    print("▶ [错误测试] 签名错误")
    timestamp = int(time.time())
    data = {
        "title": "Bad",
        "content": "Signature",
        "public_key_b64": public_key_b64,
        "signature_b64": "deadbeef",  # 错误签名
        "timestamp": timestamp
    }
    r = requests.post(f"{BASE_URL}/api/posts", json=data)
    print(r.status_code, r.json())

    print("▶ [错误测试] 无此 post_id 评论")
    r = test_create_comment(9999999, "will fail")

def main():
    # 1. 发帖
    r1 = test_create_post("Hello World", "Test blockchain post.")
    post_id = r1.json().get("post_id")
    # 2. 发2条评论
    test_create_comment(post_id, "first reply")
    test_create_comment(post_id, "second reply")
    # 3. 发新帖
    r2 = test_create_post("Second post", "This is another post.")
    post2_id = r2.json().get("post_id")
    # 4. 查询所有帖子
    test_list_posts()
    # 5. 查询单个帖子及其评论
    test_get_post_with_comments(post_id)
    # 6. 错误情况测试
    test_error_cases()
if __name__ == "__main__":
    main()







import requests
import json
import nacl.signing
import nacl.encoding
import base64
import time
import os
import hashlib
import getpass
API_BASE = "http://127.0.0.1:5000"
###########################################
## 密钥管理
class UserKey:
    def __init__(self, priv_obj: nacl.signing.SigningKey):
        self.priv = priv_obj
        self.pub = priv_obj.verify_key
    @staticmethod
    def generate():
        return UserKey(nacl.signing.SigningKey.generate())
    @staticmethod
    def from_b64(b64str):
        keybytes = base64.b64decode(b64str)
        return UserKey(nacl.signing.SigningKey(keybytes))

    @staticmethod
    def load_from_file(filepath):
        with open(filepath, "rb") as f:
            keybytes = f.read()
            return UserKey(nacl.signing.SigningKey(keybytes))

    def save(self, filepath):
        with open(filepath, "wb") as f:
            f.write(bytes(self.priv))

    def pub_b64(self):
        return base64.b64encode(bytes(self.pub)).decode()

    def get_addr(self):
        return hashlib.sha256(bytes(self.pub)).hexdigest()
def choose_key():
    while True:
        print("选择密钥来源: ")
        print("1. 生成新密钥")
        print("2. 输入base64格式私钥")
        print("3. 加载本地私钥文件(user.key)")
        print("0. 取消")
        c = input("选择: ").strip()
        try:
            if c == "1":
                key = UserKey.generate()
                key.save("user.key")
                print("新私钥已生成并保存在 user.key")
                return key
            elif c == "2":
                b64s = getpass.getpass("请输入base64格式私钥(不会回显): ").strip()
                try:
                    key = UserKey.from_b64(b64s)
                except Exception:
                    print("格式错误！")
                    continue
                return key
            elif c == "3":
                if not os.path.exists("user.key"):
                    print("user.key 文件不存在!")
                    continue
                return UserKey.load_from_file("user.key")
            elif c == "0":
                return None
        except Exception as e:
            print("操作失败：", e)
            continue
def ensure_key(obj=None):
    if obj is not None:
        return obj
    return choose_key()
###########################################
## 签名与接口调用
def sign_post(priv, title, content, timestamp):
    msg = (title + "\n" + content + "\n" + str(timestamp)).encode("utf-8")
    signature = priv.sign(msg).signature
    return base64.b64encode(signature).decode()
def sign_comment(priv, post_id, content, timestamp):
    msg = ("COMMENT\n" + str(post_id) + "\n" + content + "\n" + str(timestamp)).encode("utf-8")
    signature = priv.sign(msg).signature
    return base64.b64encode(signature).decode()
def post_create(curr_key):
    print("---- 创建新帖子 ----")
    title = input("标题：").strip()
    content = input("内容：").strip()
    timestamp = int(time.time())
    payload = {
        "title": title,
        "content": content,
        "timestamp": timestamp,
        "public_key_b64": curr_key.pub_b64(),
        "signature_b64": sign_post(curr_key.priv, title, content, timestamp)
    }
    r = requests.post(f"{API_BASE}/api/posts", json=payload)
    if r.ok:
        print("发布成功，帖子ID:", r.json()["post_id"])
    else:
        print("失败：", r.text)
def post_comment(curr_key):
    post_id = int(input("输入要评论的帖子ID: ").strip())
    content = input("评论内容：").strip()
    timestamp = int(time.time())
    payload = {
        "content": content,
        "timestamp": timestamp,
        "public_key_b64": curr_key.pub_b64(),
        "signature_b64": sign_comment(curr_key.priv, post_id, content, timestamp)
    }
    r = requests.post(f"{API_BASE}/api/posts/{post_id}/comment", json=payload)
    if r.ok:
        print("评论成功！评论ID:", r.json()["comment_id"])
    else:
        print("失败：", r.text)
def list_posts():
    print("---- 所有帖子 ----")
    r = requests.get(f"{API_BASE}/api/posts")
    items = r.json()
    for post in items:
        print(f"ID {post['id']} | 评论数: {post['comments_count']} | {post['title']}\n{post['content']}\n"
              f"作者: {post['address'][:8]}... 时间: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(post['timestamp']))}")
        print("-" * 45)
    print("共", len(items), "条")
def show_post():
    post_id = int(input("输入要查看的帖子ID: ").strip())
    r = requests.get(f"{API_BASE}/api/posts/{post_id}")
    if r.status_code != 200:
        print("未找到帖子")
        return
    post = r.json()
    print(f"==== {post['id']} ====")
    print(post["title"])
    print(post["content"])
    print("作者:", post['address'])
    print("创建时间:", time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(post['timestamp'])))
    print(f"评论数: {len(post['comments'])}")
    for idx, comment in enumerate(post['comments']):
        print(f"--- #{idx + 1} --- @ {comment['address'][:8]}...  {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(comment['timestamp']))}")
        print(comment["content"])
        print("-" * 40)
def export_all():
    print("导出全部帖子和评论（posts.json, comments.json）")
    r1 = requests.get(f"{API_BASE}/export/posts")
    r2 = requests.get(f"{API_BASE}/export/comments")
    with open("posts.json", "w", encoding="utf8") as f:
        f.write(r1.text)
    with open("comments.json", "w", encoding="utf8") as f:
        f.write(r2.text)
    print("导出成功！")
def download_db():
    print("下载论坛数据库 forum.db ...")
    r = requests.get(f"{API_BASE}/download/forum.db")
    with open("forum.db", "wb") as f:
        f.write(r.content)
    print("下载成功：forum.db")
###########################################
## 完整性校验工具
def sha256(data):
    return hashlib.sha256(data).hexdigest()
def check_blockchain(posts, comments, verbose=True):
    ok = True
    # 检查posts链
    prev_hash = "GENESIS"
    for idx, post in enumerate(posts):
        address = post["address"]
        block_hash_raw = (
            post['title'] + "\n" + post['content'] + "\n"
            + post["address"] + "\n"
            + str(post["timestamp"]) + "\n"
            + post["public_key_b64"] + "\n"
            + post["signature_b64"] + "\n"
            + prev_hash
        ).encode("utf-8")
        calc_hash = sha256(block_hash_raw)
        if calc_hash != post["block_hash"]:
            ok = False
            if verbose:
                print(f"[篡改] Post id={post['id']} block_hash错误!")
        if prev_hash != post["prev_hash"]:
            ok = False
            if verbose:
                print(f"[链断裂] Post id={post['id']} prev_hash不合规!")
        prev_hash = post["block_hash"]
    # 检查每个帖子的评论链
    post2comments = {}
    for c in comments:
        post2comments.setdefault(c["post_id"], []).append(c)
    for post_id, clist in post2comments.items():
        prev_hash = "GENESIS"
        for idx, c in enumerate(clist):
            block_hash_raw = (
                str(c["post_id"]) + "\n" + c["content"] + "\n"
                + c["address"] + "\n"
                + str(c["timestamp"]) + "\n"
                + c["public_key_b64"] + "\n"
                + c["signature_b64"] + "\n"
                + prev_hash
            ).encode("utf-8")
            calc_hash = sha256(block_hash_raw)
            if calc_hash != c["block_hash"]:
                ok = False
                if verbose:
                    print(f"[篡改] Comment id={c['id']} block_hash错误!")
            if prev_hash != c["prev_hash"]:
                ok = False
                if verbose:
                    print(f"[链断裂] Comment id={c['id']} prev_hash不合规!")
            prev_hash = c["block_hash"]

    print("[完整性校验] 区块数据", "一致" if ok else "存在异常！")
    return ok
def verify_signatures(posts, comments, verbose=True):
    # 验签
    import nacl.exceptions
    def sig_post(p):
        msg = (p["title"] + "\n" + p["content"] + "\n" + str(p["timestamp"])).encode("utf-8")
        try:
            pub = nacl.signing.VerifyKey(base64.b64decode(p["public_key_b64"]))
            sig = base64.b64decode(p["signature_b64"])
            pub.verify(msg, sig)
            return True
        except nacl.exceptions.BadSignatureError:
            return False
        except Exception:
            return False
    def sig_comment(c):
        msg = ("COMMENT\n" + str(c["post_id"]) + "\n" + c["content"] + "\n" + str(c["timestamp"])).encode("utf-8")
        try:
            pub = nacl.signing.VerifyKey(base64.b64decode(c["public_key_b64"]))
            sig = base64.b64decode(c["signature_b64"])
            pub.verify(msg, sig)
            return True
        except nacl.exceptions.BadSignatureError:
            return False
        except Exception:
            return False
    ok = True
    for p in posts:
        if not sig_post(p):
            ok = False
            if verbose:
                print(f"[签名异常] Post id={p['id']}")
    for c in comments:
        if not sig_comment(c):
            ok = False
            if verbose:
                print(f"[签名异常] Comment id={c['id']}")
    print("[签名校验] 数据", "全部合法" if ok else "存在异常！")
    return ok
def check_integrity():
    print("正在下载帖子和评论...")
    r1 = requests.get(f"{API_BASE}/export/posts")
    r2 = requests.get(f"{API_BASE}/export/comments")
    posts = json.loads(r1.content)
    comments = json.loads(r2.content)
    print("---- 数据完整性检查 ----")
    chain_ok = check_blockchain(posts, comments)
    sig_ok = verify_signatures(posts, comments)
    if chain_ok and sig_ok:
        print("所有数据完整、可追溯，未检测到被篡改/伪造/删除！")
    else:
        print("★ 检查警告：检测到数据异常，注意数据库可能遭破坏！")
###########################################
## 菜单驱动主程序
def show_menu():
    print("""
======== 区块链论坛客户端 ========
1. 密钥管理
2. 列表帖子
3. 查看帖子详细+评论
4. 创建新帖子
5. 评论帖子
6. 导出所有帖子和评论
7. 下载数据库 forum.db
8. 校验论坛完整性（检验是否被篡改/窜改/删除）
0. 退出
""")
def show_key_info(curr_key):
    print(f"当前密钥公钥_base64:  {curr_key.pub_b64()}")
    print(f"当前密钥地址_hex:   {curr_key.get_addr()}")
    print("如需保存，可写入 user.key，再用3号菜单加载。")
def main():
    curr_key = None
    while True:
        show_menu()
        try:
            choice = int(input("选择功能: ").strip())
        except Exception:
            continue
        if choice == 1:
            curr_key = choose_key()
            if curr_key:
                show_key_info(curr_key)
        elif choice == 2:
            list_posts()
        elif choice == 3:
            show_post()
        elif choice == 4:
            if not curr_key:
                print("请先加载或生成密钥！（用1号功能）")
                continue
            post_create(curr_key)
        elif choice == 5:
            if not curr_key:
                print("请先加载或生成密钥！（用1号功能）")
                continue
            post_comment(curr_key)
        elif choice == 6:
            export_all()
        elif choice == 7:
            download_db()
        elif choice == 8:
            check_integrity()
        elif choice == 0:
            break
        else:
            continue
if __name__ == "__main__":
    main()
