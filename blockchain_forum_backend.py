from flask import Flask, request, jsonify, Response
from sqlalchemy import create_engine, Column, Integer, String, Text, ForeignKey
from sqlalchemy.orm import sessionmaker, relationship, declarative_base
import nacl.signing
import hashlib
import base64
import time
import os
import json

DATABASE_URL = "sqlite:///forum.db"
SIGNATURE_VALID_WINDOW = 300  # 允许签名时间窗口，单位秒

app = Flask(__name__)
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
Base = declarative_base()
Session = sessionmaker(bind=engine)
session = Session()

# ===========================
# 数据模型
# ===========================
class Post(Base):
    __tablename__ = "posts"
    id = Column(Integer, primary_key=True)
    title = Column(String(200))
    content = Column(Text)
    address = Column(String(64))
    public_key_b64 = Column(Text)
    signature_b64 = Column(Text)
    timestamp = Column(Integer)
    block_hash = Column(String(64))
    prev_hash = Column(String(64))
    comments = relationship("Comment", back_populates="post", cascade="all, delete-orphan")
class Comment(Base):
    __tablename__ = "comments"
    id = Column(Integer, primary_key=True)
    post_id = Column(Integer, ForeignKey("posts.id"))
    content = Column(Text)
    address = Column(String(64))
    public_key_b64 = Column(Text)
    signature_b64 = Column(Text)
    timestamp = Column(Integer)
    block_hash = Column(String(64))
    prev_hash = Column(String(64))
    post = relationship("Post", back_populates="comments")
Base.metadata.create_all(engine)
# ===========================
# 工具函数
# ===========================
def b64decode(text):
    return base64.b64decode(text)
def sha256(data):
    return hashlib.sha256(data).hexdigest()
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
def get_last_post_hash():
    last_post = session.query(Post).order_by(Post.id.desc()).first()
    if last_post:
        return last_post.block_hash
    return "GENESIS"
def get_last_comment_hash(post_id):
    last_comment = (
        session.query(Comment)
        .filter_by(post_id=post_id)
        .order_by(Comment.id.desc())
        .first()
    )
    if last_comment:
        return last_comment.block_hash
    return "GENESIS"
# ===========================
# 路由：发帖接口
# ===========================
@app.route("/api/posts", methods=["POST"])
def create_post():
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
    now = int(time.time())
    if abs(now - timestamp) > SIGNATURE_VALID_WINDOW:
        return jsonify({"error": "timestamp outside allowed window"}), 400
    message = (title + "\n" + content + "\n" + str(timestamp)).encode("utf-8")
    if not verify_signature(public_key_b64, signature_b64, message):
        return jsonify({"error": "invalid signature"}), 400
    address = address_from_public_key(public_key_b64)
    prev_hash = get_last_post_hash()
    block_hash = calculate_post_block_hash(
        title, content, address, public_key_b64, signature_b64, timestamp, prev_hash
    )
    post = Post(
        title=title,
        content=content,
        address=address,
        public_key_b64=public_key_b64,
        signature_b64=signature_b64,
        timestamp=timestamp,
        block_hash=block_hash,
        prev_hash=prev_hash,
    )
    session.add(post)
    session.commit()
    return jsonify({"status": "ok", "post_id": post.id}), 201
# ===========================
# 路由：发评论接口
# ===========================
@app.route("/api/posts/<int:post_id>/comment", methods=["POST"])
def create_comment(post_id):
    post = session.query(Post).get(post_id)
    if not post:
        return jsonify({"error": "not found"}), 404
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
    now = int(time.time())
    if abs(now - timestamp) > SIGNATURE_VALID_WINDOW:
        return jsonify({"error": "timestamp outside allowed window"}), 400
    message = ("COMMENT\n" + str(post_id) + "\n" + content + "\n" + str(timestamp)).encode("utf-8")
    if not verify_signature(public_key_b64, signature_b64, message):
        return jsonify({"error": "invalid signature"}), 400
    address = address_from_public_key(public_key_b64)
    prev_hash = get_last_comment_hash(post_id)
    block_hash = calculate_comment_block_hash(
        post_id, content, address, public_key_b64, signature_b64, timestamp, prev_hash
    )
    comment = Comment(
        post_id=post_id,
        content=content,
        address=address,
        public_key_b64=public_key_b64,
        signature_b64=signature_b64,
        timestamp=timestamp,
        block_hash=block_hash,
        prev_hash=prev_hash,
    )
    session.add(comment)
    session.commit()
    return jsonify({"status": "ok", "comment_id": comment.id}), 201
# ===========================
# 路由：帖子查询
# ===========================
@app.route("/api/posts", methods=["GET"])
def list_posts():
    posts = session.query(Post).order_by(Post.timestamp.desc()).all()
    results = []
    for post in posts:
        result = {
            "id": post.id,
            "title": post.title,
            "content": post.content,
            "address": post.address,
            "timestamp": post.timestamp,
            "block_hash": post.block_hash,
            "prev_hash": post.prev_hash,
            "comments_count": len(post.comments),
        }
        results.append(result)
    return jsonify(results)
@app.route("/api/posts/<int:post_id>", methods=["GET"])
def get_post(post_id):
    post = session.query(Post).get(post_id)
    if not post:
        return jsonify({"error": "not found"}), 404
    comments = []
    sorted_comments = sorted(post.comments, key=lambda c: c.timestamp)
    for comment in sorted_comments:
        comment_info = {
            "id": comment.id,
            "content": comment.content,
            "address": comment.address,
            "timestamp": comment.timestamp,
            "block_hash": comment.block_hash,
            "prev_hash": comment.prev_hash,
        }
        comments.append(comment_info)
    return jsonify({
        "id": post.id,
        "title": post.title,
        "content": post.content,
        "address": post.address,
        "timestamp": post.timestamp,
        "block_hash": post.block_hash,
        "prev_hash": post.prev_hash,
        "comments": comments,
    })
# ===========================
# 路由：导出数据接口
# ===========================
@app.route("/export/posts", methods=["GET"])
def export_posts():
    posts = session.query(Post).order_by(Post.id.asc()).all()
    results = []
    for post in posts:
        post_info = {
            "id": post.id,
            "title": post.title,
            "content": post.content,
            "address": post.address,
            "public_key_b64": post.public_key_b64,
            "signature_b64": post.signature_b64,
            "timestamp": post.timestamp,
            "block_hash": post.block_hash,
            "prev_hash": post.prev_hash,
        }
        results.append(post_info)
    return Response(json.dumps(results, indent=2, ensure_ascii=False), content_type="application/json")
@app.route("/export/comments", methods=["GET"])
def export_comments():
    comments = session.query(Comment).order_by(Comment.id.asc()).all()
    results = []
    for comment in comments:
        comment_info = {
            "id": comment.id,
            "post_id": comment.post_id,
            "content": comment.content,
            "address": comment.address,
            "public_key_b64": comment.public_key_b64,
            "signature_b64": comment.signature_b64,
            "timestamp": comment.timestamp,
            "block_hash": comment.block_hash,
            "prev_hash": comment.prev_hash,
        }
        results.append(comment_info)
    return Response(json.dumps(results, indent=2, ensure_ascii=False), content_type="application/json")
# ===========================
# MAIN
# ===========================
if __name__ == "__main__":
    app.run(port=5000, debug=True)
