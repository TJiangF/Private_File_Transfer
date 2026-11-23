import hashlib
import hmac
import html
import json
import mimetypes
import os
import re
import secrets
import shutil
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.middleware.sessions import SessionMiddleware

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("TRANSFER_DATA_DIR", os.path.join(APP_DIR, "data"))
FILES_DIR = os.path.join(DATA_DIR, "files")
META_FILE = os.path.join(DATA_DIR, "files.json")
TOKENS_FILE = os.path.join(DATA_DIR, "api_tokens.json")
USERS_FILE = os.environ.get("TRANSFER_USERS_FILE", "/opt/ssb-monitor/data/users.json")
RETENTION_DAYS = float(os.environ.get("TRANSFER_RETENTION_DAYS", "3"))
CLEAN_INTERVAL = int(os.environ.get("TRANSFER_CLEAN_INTERVAL", "300"))
MAX_LOGIN_FAILS = int(os.environ.get("TRANSFER_MAX_LOGIN_FAILS", "5"))
LOGIN_LOCK_SECONDS = int(os.environ.get("TRANSFER_LOGIN_LOCK_SECONDS", "600"))
SESSION_MAX_AGE = int(os.environ.get("TRANSFER_SESSION_MAX_AGE", str(7 * 24 * 3600)))

os.makedirs(FILES_DIR, exist_ok=True)


def _session_secret():
    configured = os.environ.get("TRANSFER_WEB_SECRET", "").strip()
    if configured:
        return configured
    path = os.path.join(DATA_DIR, "session_secret")
    if os.path.exists(path):
        try:
            return open(path, "r").read().strip()
        except Exception:
            pass
    value = secrets.token_urlsafe(48)
    with open(path, "w") as f:
        f.write(value)
    os.chmod(path, 0o600)
    return value


app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(
    SessionMiddleware,
    secret_key=_session_secret(),
    session_cookie="transfer_session",
    same_site="lax",
    https_only=True,
    max_age=SESSION_MAX_AGE,
)

_META_LOCK = threading.RLock()
_TOKEN_LOCK = threading.RLock()
_LOGIN_LOCK = threading.RLock()
_LOGIN_FAILS = {}
_LOGIN_BLOCK_UNTIL = {}

BASE_CSS = """
* { box-sizing: border-box; }
body { margin: 0; background: #f5f7fb; color: #1f2937; font-family: -apple-system, BlinkMacSystemFont, "PingFang SC", "Microsoft YaHei", sans-serif; }
.wrap { max-width: 960px; margin: 0 auto; padding: 24px 16px 48px; }
.top { display: flex; align-items: center; justify-content: space-between; gap: 16px; margin-bottom: 20px; }
h1 { font-size: 24px; margin: 0 0 4px; }
.sub { color: #6b7280; font-size: 14px; }
.card { background: #fff; border: 1px solid #e5e7eb; border-radius: 14px; padding: 18px; margin-bottom: 16px; box-shadow: 0 4px 16px rgba(15, 23, 42, .05); }
.card h2 { font-size: 16px; margin: 0 0 14px; }
.upload { display: flex; flex-wrap: wrap; align-items: center; gap: 10px; }
input[type=file] { flex: 1 1 280px; padding: 10px; border: 1px dashed #cbd5e1; border-radius: 10px; background: #f8fafc; }
label.check { display: inline-flex; align-items: center; gap: 6px; font-size: 14px; color: #334155; }
button { border: 0; border-radius: 9px; padding: 9px 16px; background: #2563eb; color: #fff; cursor: pointer; font-size: 14px; }
button.gray { background: #eef2f7; color: #334155; }
button.red { background: #fee2e2; color: #b91c1c; }
button.small { padding: 6px 10px; font-size: 12px; }
.notice { background: #ecfdf5; color: #047857; border: 1px solid #a7f3d0; padding: 10px 12px; border-radius: 10px; margin-bottom: 14px; font-size: 14px; }
.err { background: #fef2f2; color: #b91c1c; border: 1px solid #fecaca; padding: 10px 12px; border-radius: 10px; margin-bottom: 14px; font-size: 14px; }
.token { display: block; background: #0f172a; color: #e2e8f0; padding: 12px; border-radius: 10px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; word-break: break-all; font-size: 13px; margin: 10px 0; }
.inline { display: inline; }
table { width: 100%; border-collapse: collapse; font-size: 14px; }
th, td { padding: 10px 8px; border-bottom: 1px solid #eef2f7; text-align: left; vertical-align: middle; }
th { color: #64748b; font-weight: 600; background: #f8fafc; }
td.name { max-width: 280px; word-break: break-all; }
.actions { display: flex; gap: 6px; flex-wrap: wrap; }
.actions form { margin: 0; }
.actions button { padding: 6px 10px; font-size: 12px; }
a { color: #2563eb; text-decoration: none; }
.muted { color: #94a3b8; font-size: 12px; }
.login { max-width: 420px; margin: 80px auto; }
.login .card { padding: 26px; }
.login input[type=email], .login input[type=password] { width: 100%; padding: 10px 12px; border: 1px solid #cbd5e1; border-radius: 9px; margin: 6px 0 14px; font-size: 14px; }
@media (max-width: 640px) {
  .wrap { padding: 16px 10px 36px; }
  table, thead, tbody, tr, th, td { display: block; }
  thead { display: none; }
  tr { border-bottom: 1px solid #e5e7eb; padding: 8px 0; }
  td { border: 0; padding: 4px 0; }
  td::before { content: attr(data-label) ": "; color: #94a3b8; display: inline-block; width: 82px; }
}
"""


def esc(value):
    return html.escape(str(value or ""), quote=True)


def _now():
    return datetime.now(timezone.utc)


def _iso(dt):
    return dt.isoformat()


def _parse_dt(value):
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def _load_users():
    try:
        with open(USERS_FILE, "r") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _verify_pw(pw, salt, stored):
    try:
        calc = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), bytes.fromhex(salt), 150000).hex()
        return hmac.compare_digest(calc, stored or "")
    except Exception:
        return False


def _client_ip(request):
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        return xff.split(",")[0].strip()
    real = request.headers.get("x-real-ip", "")
    if real:
        return real.strip()
    return request.client.host if request.client else "unknown"


def _login_blocked(ip):
    with _LOGIN_LOCK:
        return time.time() < float(_LOGIN_BLOCK_UNTIL.get(ip, 0))


def _login_fail(ip):
    with _LOGIN_LOCK:
        n = int(_LOGIN_FAILS.get(ip, 0)) + 1
        _LOGIN_FAILS[ip] = n
        if n >= MAX_LOGIN_FAILS:
            _LOGIN_BLOCK_UNTIL[ip] = time.time() + LOGIN_LOCK_SECONDS
            _LOGIN_FAILS[ip] = 0


def _login_ok(ip):
    with _LOGIN_LOCK:
        _LOGIN_FAILS.pop(ip, None)
        _LOGIN_BLOCK_UNTIL.pop(ip, None)


def _current_user(request):
    email = request.session.get("user")
    if not email:
        return None
    user = _load_users().get(email)
    if not user or user.get("role") != "admin":
        return None
    return user


def _read_meta_unlocked():
    try:
        with open(META_FILE, "r") as f:
            data = json.load(f)
        if isinstance(data, dict) and isinstance(data.get("files"), list):
            return data["files"]
    except Exception:
        pass
    return []


def _write_meta_unlocked(files):
    tmp = META_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"files": files}, f, ensure_ascii=False, indent=1)
    os.replace(tmp, META_FILE)


def _token_hash(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _read_tokens_unlocked():
    try:
        with open(TOKENS_FILE, "r") as f:
            data = json.load(f)
        if isinstance(data, dict) and isinstance(data.get("tokens"), list):
            return [str(x) for x in data["tokens"]]
    except Exception:
        pass
    return []


def _write_tokens_unlocked(tokens):
    tmp = TOKENS_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"tokens": tokens}, f, ensure_ascii=False, indent=1)
    os.replace(tmp, TOKENS_FILE)


def _api_token_valid(token):
    if not token:
        return False
    digest = _token_hash(token)
    with _TOKEN_LOCK:
        return any(hmac.compare_digest(digest, x) for x in _read_tokens_unlocked())


def _create_api_token():
    token = secrets.token_urlsafe(36)
    digest = _token_hash(token)
    with _TOKEN_LOCK:
        tokens = _read_tokens_unlocked()
        tokens.append(digest)
        _write_tokens_unlocked(tokens)
    return token


def _revoke_api_tokens():
    with _TOKEN_LOCK:
        _write_tokens_unlocked([])


def _api_token_from_request(request):
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:].strip()
    return request.headers.get("x-transfer-token", "").strip()


def _safe_name(name):
    value = os.path.basename((name or "file").replace("\\", "/"))
    value = re.sub(r"[\x00-\x1f/\\]", "_", value).strip()
    if not value:
        value = "file"
    if len(value) > 180:
        value = value[:180]
    return value


def _safe_ext(name):
    ext = os.path.splitext(name)[1][:20]
    if re.fullmatch(r"\.[A-Za-z0-9]{1,12}", ext):
        return ext
    return ""


def _blob_path(rec):
    blob = os.path.basename(rec.get("blob") or "")
    if not blob:
        return None
    path = os.path.abspath(os.path.join(FILES_DIR, blob))
    if not path.startswith(os.path.abspath(FILES_DIR) + os.sep):
        return None
    return path


def _expiry_dt(rec):
    if rec.get("permanent"):
        return None
    exp = _parse_dt(rec.get("expires_at"))
    if exp:
        return exp
    uploaded = _parse_dt(rec.get("uploaded_at"))
    if uploaded:
        return uploaded + timedelta(days=RETENTION_DAYS)
    return None


def _is_expired(rec, now=None):
    exp = _expiry_dt(rec)
    if exp is None:
        return False
    return exp <= (now or _now())


def cleanup_expired():
    now = _now()
    with _META_LOCK:
        files = _read_meta_unlocked()
        keep = []
        changed = False
        for rec in files:
            if _is_expired(rec, now):
                path = _blob_path(rec)
                if path and os.path.exists(path):
                    try:
                        os.remove(path)
                    except Exception:
                        pass
                changed = True
                continue
            keep.append(rec)
        if changed:
            _write_meta_unlocked(keep)
        return keep


def _cleanup_worker():
    while True:
        time.sleep(CLEAN_INTERVAL)
        try:
            cleanup_expired()
        except Exception:
            pass


@app.on_event("startup")
def _startup():
    cleanup_expired()
    threading.Thread(target=_cleanup_worker, daemon=True).start()


def _human_size(size):
    try:
        n = float(size)
    except Exception:
        n = 0
    units = ["B", "KB", "MB", "GB", "TB"]
    idx = 0
    while n >= 1024 and idx < len(units) - 1:
        n /= 1024
        idx += 1
    if idx == 0:
        return f"{int(n)} {units[idx]}"
    return f"{n:.1f} {units[idx]}"


def _human_left(rec):
    if rec.get("permanent"):
        return "长期有效"
    exp = _expiry_dt(rec)
    if not exp:
        return "—"
    seconds = (exp - _now()).total_seconds()
    if seconds <= 0:
        return "即将删除"
    if seconds >= 86400:
        return f"{int(seconds // 86400)} 天 {int((seconds % 86400) // 3600)} 小时"
    if seconds >= 3600:
        return f"{int(seconds // 3600)} 小时 {int((seconds % 3600) // 60)} 分钟"
    return f"{max(1, int(seconds // 60))} 分钟"


def _render_rows(files):
    if not files:
        return '<tr><td colspan="6" class="muted">还没有文件</td></tr>'
    rows = []
    for rec in sorted(files, key=lambda x: x.get("uploaded_at") or "", reverse=True):
        fid = esc(rec.get("id"))
        name = esc(rec.get("name") or "file")
        size = esc(_human_size(rec.get("size") or 0))
        uploaded = esc(str(rec.get("uploaded_at") or "")[:19].replace("T", " "))
        left = esc(_human_left(rec))
        perm = bool(rec.get("permanent"))
        toggle_value = "0" if perm else "1"
        toggle_text = "设为临时" if perm else "设为长期"
        rows.append(
            f'<tr><td data-label="文件" class="name"><a href="/files/{fid}/download">{name}</a><br>'
            f'<span class="muted">{size}</span></td>'
            f'<td data-label="上传时间">{uploaded}</td>'
            f'<td data-label="有效期">{left}</td>'
            f'<td data-label="状态">{"长期" if perm else "临时"}</td>'
            f'<td data-label="操作"><div class="actions">'
            f'<a href="/files/{fid}/download"><button type="button">下载</button></a>'
            f'<form method="post" action="/files/{fid}/permanent">'
            f'<input type="hidden" name="permanent" value="{toggle_value}">'
            f'<button type="submit" class="gray">{toggle_text}</button></form>'
            f'<form method="post" action="/files/{fid}/delete">'
            f'<button type="submit" class="red">删除</button></form>'
            f'</div></td></tr>'
        )
    return "".join(rows)


def _login_page(error="", email=""):
    error_html = f'<div class="err">{esc(error)}</div>' if error else ""
    return HTMLResponse(f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Private File Transfer · 登录</title>
<style>{BASE_CSS}</style></head><body>
<div class="wrap login"><div class="card">
<h1>Private File Transfer</h1>
<div class="sub">请使用 lease.tfworks.cn 管理员账号登录</div>
{error_html}
<form method="post" action="/login">
<label>邮箱</label>
<input type="email" name="email" value="{esc(email)}" required autocomplete="username">
<label>密码</label>
<input type="password" name="pw" required autocomplete="current-password">
<button type="submit" style="width:100%">登录</button>
</form>
</div></div></body></html>""")


def _redirect_msg(msg):
    return RedirectResponse("/?msg=" + quote(msg), status_code=303)


def _token_page(token):
    return HTMLResponse(f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Private File Transfer · 新令牌</title>
<style>{BASE_CSS}</style></head><body>
<div class="wrap login"><div class="card">
<h1>新 API 令牌</h1>
<div class="sub">只显示这一次，请立即保存到 macOS Keychain。</div>
<code class="token">{esc(token)}</code>
<div class="muted">保存命令：<br>~/bin/transfer-upload --set-token &lt;TOKEN&gt;</div>
<p><a href="/">返回文件列表</a></p>
</div></div></body></html>""")


def _page(user, files, msg=""):
    notice = f'<div class="notice">{esc(msg)}</div>' if msg else ""
    with _TOKEN_LOCK:
        token_count = len(_read_tokens_unlocked())
    return HTMLResponse(f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Private File Transfer</title>
<style>{BASE_CSS}</style></head><body>
<div class="wrap">
<div class="top"><div><h1>Private File Transfer</h1>
<div class="sub">登录：{esc(user.get("email") or user.get("name") or "admin")} · 任意设备上传 / 下载</div></div>
<form method="post" action="/logout"><button type="submit" class="gray">退出</button></form></div>
{notice}
<div class="card">
<h2>上传文件</h2>
<form class="upload" method="post" action="/upload" enctype="multipart/form-data">
<input type="file" name="files" multiple required>
<label class="check"><input type="checkbox" name="permanent" value="1"> 长期有效</label>
<button type="submit">上传</button>
</form>
<div class="muted" style="margin-top:8px">未勾选长期有效的文件保留 3 天；到期后自动删除。</div>
</div>
<div class="card">
<h2>macOS Quick Action 令牌</h2>
<div class="muted" style="margin-bottom:10px">当前有效令牌：{token_count} 个。生成后只显示一次，请存入 macOS Keychain，不要存密码。</div>
<div class="actions">
<form method="post" action="/api/token/create"><button type="submit" class="small">生成新令牌</button></form>
<form method="post" action="/api/token/revoke"><button type="submit" class="small red">吊销全部令牌</button></form>
</div>
</div>
<div class="card">
<h2>云端文件（{len(files)}）</h2>
<div style="overflow-x:auto"><table>
<thead><tr><th>文件</th><th>上传时间</th><th>有效期</th><th>状态</th><th>操作</th></tr></thead>
<tbody>{_render_rows(files)}</tbody></table></div>
</div>
<div class="muted">非长期文件保留 3 天；系统每 5 分钟自动清理一次。</div>
</div></body></html>""")


def _save_uploads(request, files, permanent, source):
    cleanup_expired()
    if not files:
        return 0, []
    created = []
    with _META_LOCK:
        meta = _read_meta_unlocked()
        for item in files:
            name = _safe_name(item.filename)
            fid = uuid.uuid4().hex
            blob = fid + _safe_ext(name)
            path = os.path.join(FILES_DIR, blob)
            try:
                with open(path, "wb") as out:
                    shutil.copyfileobj(item.file, out)
                size = os.path.getsize(path)
            except Exception:
                try:
                    if os.path.exists(path):
                        os.remove(path)
                except Exception:
                    pass
                continue
            now = _now()
            perm = permanent == "1"
            rec = {
                "id": fid,
                "name": name,
                "blob": blob,
                "size": size,
                "content_type": item.content_type or mimetypes.guess_type(name)[0] or "application/octet-stream",
                "uploaded_at": _iso(now),
                "permanent": perm,
                "expires_at": None if perm else _iso(now + timedelta(days=RETENTION_DAYS)),
                "uploader_ip": _client_ip(request),
                "source": source,
            }
            meta.append(rec)
            created.append({"id": fid, "name": name, "size": size, "permanent": perm})
        _write_meta_unlocked(meta)
    return len(created), created


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    user = _current_user(request)
    if not user:
        return _login_page()
    files = cleanup_expired()
    return _page(user, files, request.query_params.get("msg") or "")


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    if _current_user(request):
        return RedirectResponse("/", status_code=303)
    return _login_page()


@app.post("/login")
def login(request: Request, email: str = Form(""), pw: str = Form("")):
    ip = _client_ip(request)
    if _login_blocked(ip):
        return _login_page("尝试次数过多，请稍后再试", email)
    user = _load_users().get((email or "").strip().lower())
    if not user or user.get("role") != "admin" or not _verify_pw(pw, user.get("salt", ""), user.get("pw", "")):
        _login_fail(ip)
        return _login_page("邮箱或密码错误", email)
    _login_ok(ip)
    request.session["user"] = user.get("email")
    return RedirectResponse("/", status_code=303)


@app.post("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


@app.get("/logout")
def logout_get(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


@app.get("/token", response_class=HTMLResponse)
def token_page(request: Request):
    if not _current_user(request):
        return RedirectResponse("/login", status_code=303)
    token = request.session.pop("new_token", None)
    if not token:
        return RedirectResponse("/", status_code=303)
    return _token_page(token)


@app.post("/api/token/create")
def api_token_create(request: Request):
    if not _current_user(request):
        return RedirectResponse("/login", status_code=303)
    token = _create_api_token()
    request.session["new_token"] = token
    return RedirectResponse("/token", status_code=303)


@app.post("/api/token/revoke")
def api_token_revoke(request: Request):
    if not _current_user(request):
        return RedirectResponse("/login", status_code=303)
    _revoke_api_tokens()
    return _redirect_msg("已吊销全部 API 令牌")


@app.post("/api/upload")
def api_upload(request: Request, files: list[UploadFile] = File(...), permanent: str = Form("")):
    token = _api_token_from_request(request)
    if not _api_token_valid(token):
        return JSONResponse({"ok": False, "msg": "unauthorized"}, status_code=401)
    if not files:
        return JSONResponse({"ok": False, "msg": "no files"}, status_code=400)
    count, created = _save_uploads(request, files, permanent, "api")
    if not count:
        return JSONResponse({"ok": False, "msg": "upload failed"}, status_code=500)
    return JSONResponse({"ok": True, "created": count, "files": created})


@app.post("/upload")
def upload(request: Request, files: list[UploadFile] = File(...), permanent: str = Form("")):
    if not _current_user(request):
        return RedirectResponse("/login", status_code=303)
    if not files:
        return _redirect_msg("请选择文件")
    count, _ = _save_uploads(request, files, permanent, "web")
    if count:
        return _redirect_msg(f"已上传 {count} 个文件")
    return _redirect_msg("上传失败")


@app.get("/files/{fid}/download")
def download(request: Request, fid: str):
    if not _current_user(request):
        return RedirectResponse("/login", status_code=303)
    if not re.fullmatch(r"[0-9a-f]{32}", fid):
        return HTMLResponse("非法文件 ID", status_code=400)
    files = cleanup_expired()
    rec = next((x for x in files if x.get("id") == fid), None)
    if not rec:
        return HTMLResponse("文件不存在或已过期", status_code=404)
    path = _blob_path(rec)
    if not path or not os.path.exists(path):
        with _META_LOCK:
            meta = _read_meta_unlocked()
            meta = [x for x in meta if x.get("id") != fid]
            _write_meta_unlocked(meta)
        return HTMLResponse("文件不存在或已过期", status_code=404)
    media_type = rec.get("content_type") or mimetypes.guess_type(rec.get("name") or "")[0] or "application/octet-stream"
    return FileResponse(path, filename=rec.get("name") or "file", media_type=media_type)


@app.post("/files/{fid}/permanent")
def set_permanent(request: Request, fid: str, permanent: str = Form("")):
    if not _current_user(request):
        return RedirectResponse("/login", status_code=303)
    if not re.fullmatch(r"[0-9a-f]{32}", fid):
        return HTMLResponse("非法文件 ID", status_code=400)
    cleanup_expired()
    with _META_LOCK:
        meta = _read_meta_unlocked()
        rec = next((x for x in meta if x.get("id") == fid), None)
        if not rec:
            return HTMLResponse("文件不存在", status_code=404)
        perm = permanent == "1"
        rec["permanent"] = perm
        rec["expires_at"] = None if perm else _iso(_now() + timedelta(days=RETENTION_DAYS))
        _write_meta_unlocked(meta)
    word = "已设为长期有效" if perm else "已设为临时（3 天后删除）"
    return _redirect_msg(word)


@app.post("/files/{fid}/delete")
def delete_file(request: Request, fid: str):
    if not _current_user(request):
        return RedirectResponse("/login", status_code=303)
    if not re.fullmatch(r"[0-9a-f]{32}", fid):
        return HTMLResponse("非法文件 ID", status_code=400)
    cleanup_expired()
    with _META_LOCK:
        meta = _read_meta_unlocked()
        rec = next((x for x in meta if x.get("id") == fid), None)
        if not rec:
            return HTMLResponse("文件不存在", status_code=404)
        path = _blob_path(rec)
        if path and os.path.exists(path):
            try:
                os.remove(path)
            except Exception:
                pass
        meta = [x for x in meta if x.get("id") != fid]
        _write_meta_unlocked(meta)
    return _redirect_msg("已删除")


@app.get("/favicon.ico")
def favicon():
    return Response(status_code=204)
