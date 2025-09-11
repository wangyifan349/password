# app.py
import os
import sqlite3
import bcrypt
import shutil
import uuid
from flask import (
    Flask, request, jsonify, session, send_file, abort, redirect, url_for, render_template_string
)
from werkzeug.utils import secure_filename

# ---------- 配置 ----------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE = os.path.join(BASE_DIR, "app.db")
USER_FILES_ROOT = os.path.join(BASE_DIR, "user_files")
os.makedirs(USER_FILES_ROOT, exist_ok=True)

SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "change_this_to_random")
MAX_CONTENT_LENGTH = 500 * 1024 * 1024  # 500MB

ALLOWED_EXTENSIONS = None  # None 表示允许所有文件类型

app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH

# ---------- DB Init ----------
def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash BLOB NOT NULL
    );
    """)
    conn.commit()
    conn.close()

init_db()

# ---------- 辅助函数 ----------
def hash_password(password: str) -> bytes:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

def check_password(password: str, hashed: bytes) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), hashed)

def user_root_dir(user_id: int) -> str:
    p = os.path.join(USER_FILES_ROOT, str(user_id))
    os.makedirs(p, exist_ok=True)
    return p

def safe_relpath(path: str) -> str:
    # 规范化并禁止向上访问
    if path is None:
        return ""
    p = os.path.normpath(path).lstrip(os.sep)
    if p.startswith(".."):
        raise ValueError("invalid path")
    return p

def abs_path_for_user(user_id: int, relpath: str = "") -> str:
    rel = safe_relpath(relpath) if rel else ""
    return os.path.join(user_root_dir(user_id), rel)

def allowed_file(filename: str) -> bool:
    if ALLOWED_EXTENSIONS is None:
        return True
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, username FROM users WHERE id = ?", (uid,))
    row = cur.fetchone()
    conn.close()
    if row:
        return {"id": row["id"], "username": row["username"]}
    return None

def login_user(user_id: int):
    session["user_id"] = user_id

def logout_user():
    session.pop("user_id", None)

# ---------- Auth API ----------
@app.route("/api/register", methods=["POST"])
def api_register():
    data = request.json or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if not username or not password:
        return jsonify({"error": "username and password required"}), 400
    conn = get_db()
    cur = conn.cursor()
    try:
        pw_hash = hash_password(password)
        cur.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, pw_hash))
        conn.commit()
        user_id = cur.lastrowid
        user_root_dir(user_id)
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "username exists"}), 409
    conn.close()
    return jsonify({"ok": True, "user_id": user_id})

@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.json or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if not username or not password:
        return jsonify({"error": "username and password required"}), 400
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    if not row or not check_password(password, row["password_hash"]):
        return jsonify({"error": "invalid credentials"}), 401
    login_user(row["id"])
    return jsonify({"ok": True, "user_id": row["id"]})

@app.route("/api/logout", methods=["POST"])
def api_logout():
    logout_user()
    return jsonify({"ok": True})

# ---------- File APIs ----------
def require_login():
    user = current_user()
    if not user:
        abort(401)
    return user

@app.route("/api/upload", methods=["POST"])
def api_upload():
    user = require_login()
    target = request.form.get("target", "").strip()
    try:
        rel_target = safe_relpath(target) if target else ""
    except ValueError:
        return jsonify({"error": "invalid target"}), 400
    if "files" not in request.files:
        return jsonify({"error": "no files"}), 400
    files = request.files.getlist("files")
    saved = []
    dest_root = abs_path_for_user(user["id"], rel_target)
    os.makedirs(dest_root, exist_ok=True)
    for f in files:
        if f.filename == "":
            continue
        filename = secure_filename(f.filename)
        if not allowed_file(filename):
            continue
        dest = os.path.join(dest_root, filename)
        f.save(dest)
        saved.append({"path": os.path.join(rel_target, filename) if rel_target else filename, "size": os.path.getsize(dest)})
    return jsonify({"ok": True, "saved": saved})

def dir_to_dict(base_rel: str, abs_root: str):
    items = []
    try:
        with os.scandir(abs_root) as it:
            for entry in it:
                if entry.name.startswith("."):
                    continue
                rel = os.path.join(base_rel, entry.name) if base_rel else entry.name
                if entry.is_dir(follow_symlinks=False):
                    items.append({
                        "name": entry.name,
                        "path": rel,
                        "is_dir": True,
                        "children": dir_to_dict(rel, os.path.join(abs_root, entry.name))
                    })
                else:
                    items.append({
                        "name": entry.name,
                        "path": rel,
                        "is_dir": False,
                        "size": entry.stat(follow_symlinks=False).st_size
                    })
    except FileNotFoundError:
        return []
    items.sort(key=lambda x: (not x["is_dir"], x["name"].lower()))
    return items

@app.route("/api/list", methods=["GET"])
def api_list():
    user = require_login()
    rel = request.args.get("path", "").strip()
    try:
        rel_safe = safe_relpath(rel) if rel else ""
    except ValueError:
        return jsonify({"error": "invalid path"}), 400
    abs_root = abs_path_for_user(user["id"], rel_safe)
    if not os.path.exists(abs_root):
        return jsonify({"error": "not found"}), 404
    structure = dir_to_dict(rel_safe, abs_root)
    return jsonify({"ok": True, "path": rel_safe, "children": structure, "username": user["username"]})

@app.route("/api/download", methods=["GET"])
def api_download():
    user = require_login()
    rel = request.args.get("path", "")
    if not rel:
        return jsonify({"error": "path required"}), 400
    try:
        rel_safe = safe_relpath(rel)
    except ValueError:
        return jsonify({"error": "invalid path"}), 400
    abs_p = abs_path_for_user(user["id"], rel_safe)
    if not os.path.exists(abs_p):
        return jsonify({"error": "not found"}), 404
    if os.path.isdir(abs_p):
        tmpzip = os.path.join("/tmp", f"{uuid.uuid4().hex}.zip")
        shutil.make_archive(tmpzip.replace(".zip", ""), 'zip', abs_p)
        return send_file(tmpzip, as_attachment=True, download_name=os.path.basename(rel_safe.rstrip(os.sep)) + ".zip")
    return send_file(abs_p, as_attachment=True, download_name=os.path.basename(abs_p))

@app.route("/api/delete", methods=["POST"])
def api_delete():
    user = require_login()
    data = request.json or {}
    rel = data.get("path", "")
    if not rel:
        return jsonify({"error": "path required"}), 400
    try:
        rel_safe = safe_relpath(rel)
    except ValueError:
        return jsonify({"error": "invalid path"}), 400
    abs_p = abs_path_for_user(user["id"], rel_safe)
    if not os.path.exists(abs_p):
        return jsonify({"error": "not found"}), 404
    try:
        if os.path.isdir(abs_p):
            shutil.rmtree(abs_p)
        else:
            os.remove(abs_p)
    except Exception as e:
        return jsonify({"error": "delete failed", "detail": str(e)}), 500
    return jsonify({"ok": True})

@app.route("/api/move", methods=["POST"])
def api_move():
    user = require_login()
    data = request.json or {}
    src = data.get("src", "")
    dst = data.get("dst", "")
    if not src or not dst:
        return jsonify({"error": "src and dst required"}), 400
    try:
        src_safe = safe_relpath(src)
        dst_safe = safe_relpath(dst)
    except ValueError:
        return jsonify({"error": "invalid path"}), 400
    src_abs = abs_path_for_user(user["id"], src_safe)
    dst_abs = abs_path_for_user(user["id"], dst_safe)
    if not os.path.exists(src_abs):
        return jsonify({"error": "src not found"}), 404
    # 如果目标存在且为目录，则把源放入目标目录
    if os.path.isdir(dst_abs):
        final_abs = os.path.join(dst_abs, os.path.basename(src_abs))
        final_rel = os.path.join(dst_safe, os.path.basename(src_safe))
    else:
        parent = os.path.dirname(dst_abs)
        os.makedirs(parent, exist_ok=True)
        final_abs = dst_abs
        final_rel = dst_safe
    try:
        shutil.move(src_abs, final_abs)
    except Exception as e:
        return jsonify({"error": "move failed", "detail": str(e)}), 500
    return jsonify({"ok": True, "src": src_safe, "dst": final_rel})

# ---------- Frontend (single HTML template) ----------
INDEX_HTML = """
<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>文件管理器</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    :root{
      --accent-green:#198754;
      --accent-gold:#d4af37;
      --bg:#0f1720;
      --card-bg:#0b1220;
    }
    body{background: linear-gradient(180deg,#071018 0%, #0b1a14 100%); color:#e9f5ef;}
    .app-header{padding:1rem; display:flex; gap:1rem; align-items:center; justify-content:space-between;}
    .brand{font-weight:700; letter-spacing:0.4px;}
    .theme-btn {border-radius:999px; padding:0.35rem 0.6rem; font-weight:600;}
    .panel{background:rgba(255,255,255,0.03); border:1px solid rgba(255,255,255,0.04); padding:1rem; border-radius:10px;}
    .file-item{display:flex; align-items:center; gap:0.75rem; padding:0.45rem 0.6rem; border-radius:8px;}
    .file-item:hover{background:rgba(255,255,255,0.02);}
    .dir-badge{width:28px; height:28px; display:inline-flex; align-items:center; justify-content:center; border-radius:6px; background:rgba(255,255,255,0.03);}
    .tree {max-height:55vh; overflow:auto;}
    .drop-target{outline:2px dashed rgba(255,255,255,0.06); border-radius:8px; padding:0.5rem;}
    .file-name{flex:1; word-break:break-all;}
    .small-muted{color:rgba(255,255,255,0.45); font-size:0.85rem;}
    /* Green theme */
    .theme-green {--accent:var(--accent-green); --gold:var(--accent-gold);}
    .theme-gold {--accent:var(--accent-gold); --gold:var(--accent-green);}
    .btn-accent {background:var(--accent); color:#07200a; border:none;}
    .btn-accent:hover {opacity:0.9;}
    .accent-border {border:1px solid rgba(255,255,255,0.03);}
    .highlight {box-shadow:0 6px 18px rgba(0,0,0,0.45); border-left:4px solid var(--gold);}
    .upload-area{min-height:120px; display:flex; align-items:center; justify-content:center; text-align:center; border-radius:8px;}
    .muted {color:rgba(255,255,255,0.55);}
    .path-breadcrumb{background:rgba(0,0,0,0.35); padding:0.2rem 0.5rem; border-radius:6px;}
    .actions .btn {margin-left:0.35rem;}
  </style>
</head>
<body class="theme-green">
  <div class="container py-4">
    <div class="app-header">
      <div>
        <div class="brand">文件管理器</div>
        <div class="small-muted">私有空间 · 多文件上传 · 拖拽移动 · AJAX 操作</div>
      </div>
      <div>
        <button id="toggleTheme" class="btn theme-btn btn-outline-light">切换主题</button>
        <button id="logoutBtn" class="btn btn-light d-none">登出</button>
      </div>
    </div>

    <div class="row g-3">
      <div class="col-md-4">
        <div class="panel accent-border">
          <div class="d-flex justify-content-between align-items-center mb-2">
            <strong>账户</strong>
            <small id="usernameLabel" class="small-muted">未登录</small>
          </div>

          <div id="authArea">
            <div id="loginForm">
              <input id="loginUser" class="form-control mb-2" placeholder="用户名">
              <input id="loginPass" type="password" class="form-control mb-2" placeholder="密码">
              <div class="d-flex gap-2">
                <button id="loginBtn" class="btn btn-accent">登录</button>
                <button id="showReg" class="btn btn-outline-light">注册</button>
              </div>
            </div>
            <div id="regForm" class="d-none">
              <input id="regUser" class="form-control mb-2" placeholder="用户名">
              <input id="regPass" type="password" class="form-control mb-2" placeholder="密码">
              <div class="d-flex gap-2">
                <button id="regBtn" class="btn btn-accent">创建账户</button>
                <button id="showLogin" class="btn btn-outline-light">返回登录</button>
              </div>
            </div>
          </div>

          <hr class="my-3">
          <div>
            <strong>上传文件</strong>
            <div class="upload-area drop-target mt-2" id="uploadArea">
              <div>
                <div class="muted">将文件拖拽到此处或点击选择（多选）</div>
                <input id="fileInput" type="file" multiple class="form-control mt-2">
                <div class="small-muted mt-2">目标目录：<span id="currentPath" class="path-breadcrumb">/</span></div>
                <div class="mt-2">
                  <button id="uploadBtn" class="btn btn-accent">上传</button>
                </div>
              </div>
            </div>
            <div class="small-muted mt-2">提示：拖动文件到目录树中的文件夹以移动（拖拽节点）。</div>
          </div>
        </div>

        <div class="panel mt-3 accent-border">
          <div class="d-flex justify-content-between align-items-center mb-2">
            <strong>操作</strong>
            <div class="small-muted">快速操作</div>
          </div>
          <div class="d-flex flex-column">
            <button id="refreshBtn" class="btn btn-sm btn-outline-light mb-2">刷新列表</button>
            <button id="createFolderBtn" class="btn btn-sm btn-outline-light mb-2">新建文件夹</button>
            <button id="downloadAllBtn" class="btn btn-sm btn-outline-light mb-2">下载当前目录（ZIP）</button>
          </div>
        </div>

      </div>

      <div class="col-md-8">
        <div class="panel accent-border">
          <div class="d-flex justify-content-between mb-2">
            <strong>文件浏览</strong>
            <div class="actions">
              <span id="breadcrumb" class="small-muted path-breadcrumb">/</span>
              <button id="upBtn" class="btn btn-sm btn-outline-light">上级</button>
            </div>
          </div>

          <div class="row">
            <div class="col-md-5 border-end pe-3">
              <div class="tree" id="treeView"></div>
            </div>
            <div class="col-md-7">
              <div id="listView"></div>
            </div>
          </div>

        </div>
      </div>
    </div>

    <div class="mt-4 small-muted text-center">主题：绿色 / 金色 · 示例演示版</div>
  </div>

<script>
const api = (p, opts) => fetch(p, opts).then(r=>r.json());
let currentPath = "";
let username = null;
const setTheme = (name) => {
  document.body.classList.remove("theme-green","theme-gold");
  document.body.classList.add(name);
};
let theme = localStorage.getItem("theme") || "theme-green";
setTheme(theme);

document.getElementById("toggleTheme").addEventListener("click", ()=>{
  theme = theme === "theme-green" ? "theme-gold" : "theme-green";
  setTheme(theme); localStorage.setItem("theme", theme);
});

function showMsg(s){ alert(s); }

function updateAuthUI() {
  const user = localStorage.getItem("user");
  if (user) {
    username = user;
    document.getElementById("usernameLabel").textContent = username;
    document.getElementById("authArea").classList.add("d-none");
    document.getElementById("logoutBtn").classList.remove("d-none");
  } else {
    username = null;
    document.getElementById("usernameLabel").textContent = "未登录";
    document.getElementById("authArea").classList.remove("d-none");
    document.getElementById("logoutBtn").classList.add("d-none");
  }
}

document.getElementById("showReg").addEventListener("click", ()=>{ document.getElementById("loginForm").classList.add("d-none"); document.getElementById("regForm").classList.remove("d-none"); });
document.getElementById("showLogin").addEventListener("click", ()=>{ document.getElementById("regForm").classList.add("d-none"); document.getElementById("loginForm").classList.remove("d-none"); });

document.getElementById("regBtn").addEventListener("click", async ()=>{
  const u = document.getElementById("regUser").value.trim();
  const p = document.getElementById("regPass").value;
  if(!u||!p){ showMsg("用户名和密码不能为空"); return; }
  const res = await api("/api/register", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({username:u,password:p})});
  if(res.ok){ localStorage.setItem("user", u); updateAuthUI(); showMsg("注册成功，已登录"); refreshTree(); } else showMsg(res.error||"注册失败");
});

document.getElementById("loginBtn").addEventListener("click", async ()=>{
  const u = document.getElementById("loginUser").value.trim();
  const p = document.getElementById("loginPass").value;
  if(!u||!p){ showMsg("用户名和密码不能为空"); return; }
  const res = await api("/api/login", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({username:u,password:p})});
  if(res.ok){ localStorage.setItem("user", u); updateAuthUI(); showMsg("登录成功"); refreshTree(); } else showMsg(res.error||"登录失败");
});

document.getElementById("logoutBtn").addEventListener("click", async ()=>{
  await api("/api/logout", {method:"POST"});
  localStorage.removeItem("user"); updateAuthUI(); currentPath=""; renderTree([]); renderList([]);
});

updateAuthUI();

// drag & drop upload
const uploadArea = document.getElementById("uploadArea");
uploadArea.addEventListener("dragover", e=>{ e.preventDefault(); uploadArea.classList.add("highlight"); });
uploadArea.addEventListener("dragleave", e=>{ uploadArea.classList.remove("highlight"); });
uploadArea.addEventListener("drop", e=>{ e.preventDefault(); uploadArea.classList.remove("highlight"); const dt = e.dataTransfer; if(dt.files.length) handleFiles(dt.files); });

document.getElementById("fileInput").addEventListener("change", (e)=> handleFiles(e.target.files));
document.getElementById("uploadBtn").addEventListener("click", ()=> {
  const input = document.getElementById("fileInput");
  if(input.files.length) handleFiles(input.files);
});

function handleFiles(fileList){
  if(!localStorage.getItem("user")){ showMsg("请先登录"); return; }
  const fd = new FormData();
  for(const f of fileList) fd.append("files", f);
  fd.append("target", currentPath);
  fetch("/api/upload", {method:"POST", body:fd})
    .then(r=>r.json()).then(j=>{ if(j.ok){ showMsg("上传完成"); refreshTree(); } else showMsg(j.error||"上传失败"); })
    .catch(()=> showMsg("上传失败"));
}

// tree rendering & interactions
async function refreshTree(){
  if(!localStorage.getItem("user")) return;
  const res = await api("/api/list?path="+encodeURIComponent(currentPath||""));
  if(!res.ok){ if(res.error==="not found"){ currentPath=""; } else { /*可能401*/ } renderTree([]); renderList([]); return; }
  document.getElementById("usernameLabel").textContent = res.username || localStorage.getItem("user");
  renderTree(res.children);
  renderList(res.children);
  document.getElementById("breadcrumb").textContent = "/" + (currentPath||"");
  document.getElementById("currentPath").textContent = "/" + (currentPath||"");
}

function renderTree(items){
  const el = document.getElementById("treeView");
  el.innerHTML = "";
  const ul = document.createElement("div");
  items.forEach(item => {
    const node = createTreeNode(item);
    ul.appendChild(node);
  });
  el.appendChild(ul);
}

function createTreeNode(item){
  const div = document.createElement("div");
  div.className = "file-item";
  div.draggable = true;
  div.dataset.path = item.path;
  const icon = document.createElement("div"); icon.className="dir-badge"; icon.textContent = item.is_dir? "📂":"📄";
  const name = document.createElement("div"); name.className="file-name"; name.textContent = item.name;
  const meta = document.createElement("div"); meta.className="small-muted"; meta.textContent = item.is_dir? "文件夹": (item.size+" bytes");
  div.appendChild(icon); div.appendChild(name); div.appendChild(meta);
  if(item.is_dir){
    div.addEventListener("click", (e)=> { e.stopPropagation(); currentPath = item.path; refreshTree(); });
    // allow drop onto folder
    div.addEventListener("dragover", (e)=>{ e.preventDefault(); div.classList.add("highlight"); });
    div.addEventListener("dragleave", (e)=>{ div.classList.remove("highlight"); });
    div.addEventListener("drop", async (e)=> {
      e.preventDefault(); div.classList.remove("highlight");
      const src = e.dataTransfer.getData("text/plain");
      if(!src) return;
      // move via API
      const res = await api("/api/move", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({src:src, dst:item.path})});
      if(res.ok){ refreshTree(); } else showMsg(res.error||"移动失败");
    });
    // recursive children
    if(item.children && item.children.length){
      const childWrap = document.createElement("div");
      childWrap.style.paddingLeft = "12px";
      item.children.forEach(ch=>{
        childWrap.appendChild(createTreeNode(ch));
      });
      div.appendChild(childWrap);
    }
  } else {
    // file: drag to move
    div.addEventListener("dragstart", (e)=> { e.dataTransfer.setData("text/plain", item.path); });
    div.addEventListener("dblclick", ()=> { // 下载
      window.location = "/api/download?path="+encodeURIComponent(item.path);
    });
  }
  return div;
}

function renderList(items){
  const el = document.getElementById("listView");
  el.innerHTML = "";
  if(!items || items.length===0){ el.innerHTML = "<div class='muted'>空目录</div>"; return; }
  items.forEach(it=>{
    const row = document.createElement("div");
    row.className = "file-item";
    const icon = document.createElement("div"); icon.className="dir-badge"; icon.textContent = it.is_dir? "📁":"📄";
    const name = document.createElement("div"); name.className="file-name"; name.textContent = it.name;
    const actions = document.createElement("div");
    if(it.is_dir){
      const openBtn = document.createElement("button"); openBtn.className="btn btn-sm btn-outline-light"; openBtn.textContent="打开";
      openBtn.addEventListener("click", ()=>{ currentPath = it.path; refreshTree(); });
      actions.appendChild(openBtn);
    } else {
      const dl = document.createElement("button"); dl.className="btn btn-sm btn-outline-light"; dl.textContent="下载";
      dl.addEventListener("click", ()=> window.location = "/api/download?path="+encodeURIComponent(it.path));
      actions.appendChild(dl);
    }
    const del = document.createElement("button"); del.className="btn btn-sm btn-danger"; del.textContent="删除";
    del.addEventListener("click", async ()=> {
      if(!confirm("确认删除 "+it.path+" ?")) return;
      const res = await api("/api/delete", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({path:it.path})});
      if(res.ok) refreshTree(); else showMsg(res.error||"删除失败");
    });
    actions.appendChild(del);
    row.appendChild(icon); row.appendChild(name); row.appendChild(actions);
    // allow drag for files
    if(!it.is_dir){
      row.draggable = true;
      row.addEventListener("dragstart", (e)=> e.dataTransfer.setData("text/plain", it.path));
    } else {
      // allow drop to move here
      row.addEventListener("dragover", (e)=>{ e.preventDefault(); row.classList.add("highlight"); });
      row.addEventListener("dragleave", ()=> row.classList.remove("highlight"));
      row.addEventListener("drop", async (e)=> {
        e.preventDefault(); row.classList.remove("highlight");
        const src = e.dataTransfer.getData("text/plain");
        if(!src) return;
        const res = await api("/api/move", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({src:src, dst:it.path})});
        if(res.ok) refreshTree(); else showMsg(res.error||"移动失败");
      });
    }
    el.appendChild(row);
  });
}

document.getElementById("refreshBtn").addEventListener("click", refreshTree);
document.getElementById("upBtn").addEventListener("click", ()=>{
  if(!currentPath) return;
  const p = currentPath.split("/").slice(0,-1).join("/");
  currentPath = p;
  refreshTree();
});

document.getElementById("createFolderBtn").addEventListener("click", async ()=>{
  const name = prompt("新建文件夹名称：");
  if(!name) return;
  const dest = (currentPath?currentPath+"/":"")+name;
  // create by moving an empty temp dir: we'll create folder via upload trick (no direct API), so create via move from temp
  const res = await api("/api/move", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({src: "__create_placeholder__/"+Math.random().toString(36).slice(2), dst: dest})});
  // since backend doesn't support creating empty dir via move from nowhere, instead call backend to create dir via upload of empty file then delete it
  // simpler: use fetch to create folder by uploading a zero-byte file with folder prefix
  const fd = new FormData();
  const blob = new Blob([], {type: "application/octet-stream"});
  fd.append("files", blob, ".placeholder");
  fd.append("target", dest);
  const up = await fetch("/api/upload", {method:"POST", body:fd});
  const j = await up.json();
  if(j.ok) refreshTree();
});

document.getElementById("downloadAllBtn").addEventListener("click", ()=>{
  if(!localStorage.getItem("user")){ showMsg("请先登录"); return; }
  const p = currentPath || "";
  window.location = "/api/download?path="+encodeURIComponent(p);
});

// initial
refreshTree();
</script>
</body>
</html>
"""
@app.route("/")
def index():
    return render_template_string(INDEX_HTML)
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
