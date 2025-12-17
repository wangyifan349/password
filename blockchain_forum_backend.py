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
