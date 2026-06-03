#!/usr/bin/env python3
"""
Auth Proxy Bridge — 为没有鉴权的本地 Web 服务添加密码保护。
全平台通用 (Windows / Linux / macOS)，仅依赖 aiohttp。

所有配置通过 proxy_config.json 管理，详细文档请参阅 README.md
"""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import time
from dataclasses import dataclass, field
from aiohttp import ClientError, ClientSession, ClientTimeout, WSMsgType, web

# ═══════════════════════════════════════════════════════════════
#  配置 dataclass
# ═══════════════════════════════════════════════════════════════

@dataclass
class ProxyApp:
    """单个代理应用配置。"""
    id: str
    name: str
    url: str
    icon: str = "/icons/default.svg"
    description: str = ""


@dataclass
class ProxyConfig:
    """代理全局配置。"""
    listen_host: str = "0.0.0.0"
    listen_port: int = 8888
    auth_password: str = "admin"
    session_timeout: int = 86400
    title: str = "Proxy Bridge"
    apps: list[ProxyApp] = field(default_factory=list)

    @property
    def multi_app(self) -> bool:
        """是否为多应用仪表盘模式。"""
        return len(self.apps) > 0

    def get_app(self, app_id: str) -> ProxyApp | None:
        """按 ID 查找应用。"""
        for app in self.apps:
            if app.id == app_id:
                return app
        return None


# 模块级全局配置 (create_app 时填充)
CONFIG: ProxyConfig | None = None


def load_config() -> ProxyConfig:
    """从 proxy_config.json 加载配置。"""
    config_path = os.environ.get("PROXY_CONFIG_PATH", "proxy_config.json")

    if not os.path.isfile(config_path):
        print(f"[error] 配置文件不存在: {config_path}")
        print("请创建 proxy_config.json，参考 README.md 中的配置说明")
        import sys
        sys.exit(1)

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as exc:
        print(f"[error] 配置文件 JSON 格式错误: {exc}")
        import sys
        sys.exit(1)
    except OSError as exc:
        print(f"[error] 无法读取配置文件: {exc}")
        import sys
        sys.exit(1)

    if not isinstance(data, dict):
        print("[error] 配置文件根节点必须是 JSON 对象")
        import sys
        sys.exit(1)

    apps_raw = data.get("apps", [])
    apps = [
        ProxyApp(
            id=a["id"],
            name=a["name"],
            url=a["url"].rstrip("/"),
            icon=a.get("icon", "/icons/default.svg"),
            description=a.get("description", ""),
        )
        for a in apps_raw
    ]

    return ProxyConfig(
        listen_host=data.get("listen_host", "0.0.0.0"),
        listen_port=int(data.get("listen_port", 8888)),
        auth_password=data.get("auth_password", "admin"),
        session_timeout=int(data.get("session_timeout", 86400)),
        title=data.get("title", "Proxy Bridge"),
        apps=apps,
    )


def save_config() -> None:
    """将当前配置持久化到 proxy_config.json。"""
    config_path = os.environ.get("PROXY_CONFIG_PATH", "proxy_config.json")
    data = {
        "listen_host": CONFIG.listen_host,
        "listen_port": CONFIG.listen_port,
        "auth_password": CONFIG.auth_password,
        "session_timeout": CONFIG.session_timeout,
        "title": CONFIG.title,
        "apps": [
            {
                "id": a.id,
                "name": a.name,
                "url": a.url,
                "icon": a.icon,
                "description": a.description,
            }
            for a in CONFIG.apps
        ],
    }
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=4)


# ═══════════════════════════════════════════════════════════════
#  静态资源
# ═══════════════════════════════════════════════════════════════

_DEFAULT_ICON_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" fill="none">'
    '<rect width="64" height="64" rx="14" fill="#238636"/>'
    '<path d="M20 26h24M20 34h24M20 42h16" stroke="#fff" stroke-width="3.5" '
    'stroke-linecap="round"/>'
    '</svg>'
)


def _ensure_icons_dir() -> None:
    """确保 icons/ 目录存在，并包含默认图标。"""
    icons_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "icons")
    os.makedirs(icons_dir, exist_ok=True)
    default_path = os.path.join(icons_dir, "default.svg")
    if not os.path.exists(default_path):
        with open(default_path, "w", encoding="utf-8") as f:
            f.write(_DEFAULT_ICON_SVG)


# ═══════════════════════════════════════════════════════════════
#  Session 存储 (内存)
# ═══════════════════════════════════════════════════════════════
_sessions: dict[str, float] = {}          # token -> 过期时间戳

COOKIE_NAME = "auth_proxy_session"
PROXY_APP_COOKIE = "proxy_app"


def _new_session() -> str:
    token = secrets.token_hex(32)
    _sessions[token] = time.time() + CONFIG.session_timeout
    return token


def _valid(token: str | None) -> bool:
    if not token or token not in _sessions:
        return False
    if time.time() > _sessions[token]:
        del _sessions[token]
        return False
    return True


def _cleanup() -> None:
    """清理过期 session，防止内存泄漏。"""
    now = time.time()
    for t in [t for t, e in _sessions.items() if now > e]:
        del _sessions[t]


# ═══════════════════════════════════════════════════════════════
#  登录页 HTML
# ═══════════════════════════════════════════════════════════════
_LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>{title} - 登录</title>
<style>
    :root{{--bg:#0d1117;--card:#161b22;--border:#30363d;--text:#e6edf3;
        --text-secondary:#7d8590;--text-muted:#484f58;--accent:#58a6ff;
        --btn-primary:#238636;--btn-primary-hover:#2ea043;
        --btn-hover-bg:#21262d;--btn-hover-border:#6e7681;
        --danger:#f85149;--danger-bg:#da3633;--warning:#f0883e;--success:#3fb950;
        --input-bg:#0d1117;--shadow:rgba(0,0,0,.48);}}
    [data-theme="light"]{{--bg:#f6f8fa;--card:#fff;--border:#d0d7de;--text:#1f2328;
        --text-secondary:#656d76;--text-muted:#8b949e;--accent:#0969da;
        --btn-primary:#1f883d;--btn-primary-hover:#1a7f37;
        --btn-hover-bg:#f3f4f6;--btn-hover-border:#d0d7de;
        --danger:#cf222e;--danger-bg:#cf222e;--warning:#bf8700;--success:#1a7f37;
        --input-bg:#fff;--shadow:rgba(31,35,40,.12);}}
    *,*::before,*::after{{margin:0;padding:0;box-sizing:border-box}}
    body{{
        font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,"Noto Sans SC",sans-serif;
        background:var(--bg);color:var(--text);
        min-height:100vh;display:flex;align-items:center;justify-content:center;
        transition:background .3s,color .3s;
    }}
    .card{{
        background:var(--card);border:1px solid var(--border);border-radius:12px;
        padding:40px 36px;width:380px;max-width:92vw;
        box-shadow:0 8px 32px var(--shadow);transition:background .3s,border-color .3s;
    }}
    .card .icon{{text-align:center;font-size:40px;margin-bottom:8px}}
    .card h1{{font-size:22px;font-weight:600;text-align:center;margin-bottom:4px}}
    .card .sub{{color:var(--text-secondary);text-align:center;font-size:13px;margin-bottom:28px}}
    .field{{margin-bottom:18px}}
    .field label{{display:block;font-size:13px;font-weight:500;margin-bottom:6px}}
    .field input{{
        width:100%;padding:10px 14px;
        background:var(--input-bg);border:1px solid var(--border);border-radius:8px;
        color:var(--text);font-size:15px;outline:none;
        transition:border-color .15s,box-shadow .15s,background .3s,color .3s;
    }}
    .field input:focus{{border-color:var(--accent);box-shadow:0 0 0 3px rgba(88,166,255,.15)}}
    .field input::placeholder{{color:var(--text-muted)}}
    button{{
        width:100%;padding:11px;margin-top:6px;
        background:var(--btn-primary);color:#fff;border:1px solid rgba(240,246,252,.1);
        border-radius:8px;font-size:15px;font-weight:600;cursor:pointer;
        transition:background .15s;
    }}
    button:hover{{background:var(--btn-primary-hover)}}
    button:active{{transform:scale(.98)}}
    .error{{color:var(--danger);text-align:center;margin-top:14px;font-size:13px;display:none}}
    .error.show{{display:block}}
    .theme-toggle{{
        position:fixed;top:16px;right:16px;padding:6px 10px;
        background:var(--card);border:1px solid var(--border);border-radius:6px;
        color:var(--text-secondary);font-size:18px;cursor:pointer;
        line-height:1;transition:background .15s;
    }}
    .theme-toggle:hover{{background:var(--btn-hover-bg)}}
</style>
</head>
<body>
<div class="card">
    <div class="icon">&#128274;</div>
    <h1>{title}</h1>
    <p class="sub">请输入密码以继续访问</p>
    <form method="post" action="/login{next_qs}">
        <div class="field">
            <label for="pw">密码</label>
            <input id="pw" type="password" name="password" placeholder="输入访问密码" autofocus required>
        </div>
        <button type="submit">登 录</button>
        <p class="error{error_class}">{error_text}</p>
    </form>
</div>
<button class="theme-toggle" id="theme-toggle" title="切换主题">☀</button>
<script>
(function(){{var t=localStorage.getItem('theme')||'dark';document.documentElement.setAttribute('data-theme',t);
var b=document.getElementById('theme-toggle');b.textContent=t==='light'?'🌙':'☀';
b.addEventListener('click',function(){{var n=document.documentElement.getAttribute('data-theme')==='light'?'dark':'light';
document.documentElement.setAttribute('data-theme',n);localStorage.setItem('theme',n);b.textContent=n==='light'?'🌙':'☀';}});}})();
</script>
</body>
</html>"""


def _render_login(error: bool = False, next_url: str = "") -> str:
    return _LOGIN_HTML.format(
        title=CONFIG.title,
        next_qs=f"?next={next_url}" if next_url else "",
        error_class=" show" if error else "",
        error_text="密码不正确，请重试" if error else "",
    )


# ═══════════════════════════════════════════════════════════════
#  仪表盘 HTML
# ═══════════════════════════════════════════════════════════════
_DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>{title} - 仪表盘</title>
<style>
    :root{{--bg:#0d1117;--card:#161b22;--border:#30363d;--text:#e6edf3;
        --text-secondary:#7d8590;--text-muted:#484f58;--accent:#58a6ff;
        --btn-primary:#238636;--btn-primary-hover:#2ea043;
        --btn-hover-bg:#21262d;--btn-hover-border:#6e7681;
        --danger:#f85149;--danger-bg:#da3633;--warning:#f0883e;--success:#3fb950;
        --input-bg:#0d1117;--shadow:rgba(0,0,0,.48);}}
    [data-theme="light"]{{--bg:#f6f8fa;--card:#fff;--border:#d0d7de;--text:#1f2328;
        --text-secondary:#656d76;--text-muted:#8b949e;--accent:#0969da;
        --btn-primary:#1f883d;--btn-primary-hover:#1a7f37;
        --btn-hover-bg:#f3f4f6;--btn-hover-border:#d0d7de;
        --danger:#cf222e;--danger-bg:#cf222e;--warning:#bf8700;--success:#1a7f37;
        --input-bg:#fff;--shadow:rgba(31,35,40,.12);}}
    *,*::before,*::after{{margin:0;padding:0;box-sizing:border-box}}
    body{{
        font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,"Noto Sans SC",sans-serif;
        background:var(--bg);color:var(--text);
        min-height:100vh;transition:background .3s,color .3s;
    }}
    .container{{max-width:1200px;margin:0 auto;padding:32px 20px}}
    header{{
        display:flex;align-items:center;justify-content:space-between;
        flex-wrap:wrap;gap:12px;
        margin-bottom:32px;padding-bottom:16px;
        border-bottom:1px solid var(--border);transition:border-color .3s;
    }}
    header .header-left{{display:flex;align-items:baseline;gap:10px;flex-wrap:wrap}}
    header h1{{font-size:24px;font-weight:600}}
    header h1 span{{color:var(--text-secondary);font-weight:400;font-size:18px}}
    .header-right{{display:flex;align-items:center;gap:8px}}
    .logout-btn{{
        padding:8px 18px;background:transparent;
        color:var(--text);border:1px solid var(--border);border-radius:8px;
        font-size:13px;text-decoration:none;cursor:pointer;
        transition:background .15s,border-color .15s,color .3s;
    }}
    .logout-btn:hover{{background:var(--btn-hover-bg);border-color:var(--btn-hover-border)}}
    .theme-toggle{{
        padding:6px 10px;background:var(--card);border:1px solid var(--border);
        border-radius:6px;color:var(--text-secondary);font-size:16px;cursor:pointer;
        line-height:1;transition:background .15s,color .3s;
    }}
    .theme-toggle:hover{{background:var(--btn-hover-bg)}}
    .greeting{{font-size:13px;color:var(--text-secondary);margin-bottom:24px;text-align:center}}
    .grid{{
        display:grid;
        grid-template-columns:repeat(auto-fill,minmax(240px,1fr));
        gap:20px;
    }}
    .card{{
        background:var(--card);border:1px solid var(--border);border-radius:12px;
        padding:28px 20px;text-decoration:none;color:var(--text);
        display:flex;flex-direction:column;align-items:center;
        text-align:center;transition:border-color .2s,transform .15s,box-shadow .2s,background .3s;
        cursor:pointer;
    }}
    .card:hover{{
        border-color:var(--accent);transform:translateY(-3px);
        box-shadow:0 12px 28px rgba(88,166,255,.12);
    }}
    .card:active{{transform:scale(.97)}}
    .card-icon{{
        width:56px;height:56px;object-fit:contain;
        margin-bottom:14px;opacity:.9;
    }}
    .card-name{{font-size:17px;font-weight:600;margin-bottom:6px}}
    .card-desc{{font-size:12px;color:var(--text-secondary);line-height:1.5;max-width:200px}}
    .card-badge{{
        display:inline-block;margin-top:12px;padding:4px 14px;
        background:rgba(88,166,255,.1);color:var(--accent);
        border:1px solid rgba(88,166,255,.2);
        border-radius:20px;font-size:11px;font-weight:500;
    }}
    .empty-state{{
        text-align:center;padding:60px 20px;color:var(--text-secondary);
    }}
    .empty-state .icon{{font-size:64px;margin-bottom:16px}}
    .empty-state p{{font-size:15px;line-height:1.6}}
    .footer{{
        text-align:center;margin-top:40px;padding-top:20px;
        border-top:1px solid var(--border);color:var(--text-muted);font-size:12px;
        transition:border-color .3s,color .3s;
    }}
</style>
</head>
<body>
<div class="container">
    <header>
        <div class="header-left">
            <h1>{title} <span>仪表盘</span></h1>
        </div>
        <div class="header-right">
            <a href="/manage" class="logout-btn" style="color:var(--accent);border-color:rgba(88,166,255,.2)">管理</a>
            <button class="theme-toggle" id="theme-toggle" title="切换主题">☀</button>
            <a href="/logout" class="logout-btn">退出登录</a>
        </div>
    </header>
    <p class="greeting">共 {app_count} 个可用服务，点击卡片即可访问</p>
    <div class="grid">
        {app_cards}
    </div>
    {empty_hint}
    <div class="footer">Auth Proxy Bridge &copy; {year}</div>
</div>
<script>
(function(){{var t=localStorage.getItem('theme')||'dark';document.documentElement.setAttribute('data-theme',t);
var b=document.getElementById('theme-toggle');if(b){{b.textContent=t==='light'?'🌙':'☀';}}
b.addEventListener('click',function(){{var n=document.documentElement.getAttribute('data-theme')==='light'?'dark':'light';
document.documentElement.setAttribute('data-theme',n);localStorage.setItem('theme',n);b.textContent=n==='light'?'🌙':'☀';}});}})();
</script>
</body>
</html>"""


def _render_dashboard() -> str:
    """渲染仪表盘页面。"""
    cards: list[str] = []
    for app in CONFIG.apps:
        desc_html = f'<div class="card-desc">{app.description}</div>' if app.description else ""
        card = (
            f'<a href="/p/{app.id}/" class="card">'
            f'<img class="card-icon" src="{app.icon}" alt="{app.name}" onerror="this.src=\'/icons/default.svg\'">'
            f'<div class="card-name">{app.name}</div>'
            f'{desc_html}'
            f'<span class="card-badge">打开</span>'
            f'</a>'
        )
        cards.append(card)

    empty_hint = ""
    if not cards:
        empty_hint = (
            '<div class="empty-state">'
            '<div class="icon">📭</div>'
            '<p>暂未配置任何服务</p>'
            '<p style="font-size:13px;margin-top:6px">请编辑 proxy_config.json 添加应用</p>'
            '</div>'
        )

    import datetime
    return _DASHBOARD_HTML.format(
        title=CONFIG.title,
        app_count=len(CONFIG.apps),
        app_cards="\n        ".join(cards) if cards else "",
        empty_hint=empty_hint,
        year=datetime.datetime.now().year,
    )


# ═══════════════════════════════════════════════════════════════
#  管理页 HTML
# ═══════════════════════════════════════════════════════════════

_MANAGE_HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>{title} - 管理</title>
<style>
    :root{{--bg:#0d1117;--card:#161b22;--border:#30363d;--text:#e6edf3;
        --text-secondary:#7d8590;--text-muted:#484f58;--accent:#58a6ff;
        --btn-primary:#238636;--btn-primary-hover:#2ea043;
        --btn-hover-bg:#21262d;--btn-hover-border:#6e7681;
        --danger:#f85149;--danger-bg:#da3633;--warning:#f0883e;--success:#3fb950;
        --input-bg:#0d1117;--shadow:rgba(0,0,0,.48);}}
    [data-theme="light"]{{--bg:#f6f8fa;--card:#fff;--border:#d0d7de;--text:#1f2328;
        --text-secondary:#656d76;--text-muted:#8b949e;--accent:#0969da;
        --btn-primary:#1f883d;--btn-primary-hover:#1a7f37;
        --btn-hover-bg:#f3f4f6;--btn-hover-border:#d0d7de;
        --danger:#cf222e;--danger-bg:#cf222e;--warning:#bf8700;--success:#1a7f37;
        --input-bg:#fff;--shadow:rgba(31,35,40,.12);}}
    *,*::before,*::after{{margin:0;padding:0;box-sizing:border-box}}
    body{{
        font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,"Noto Sans SC",sans-serif;
        background:var(--bg);color:var(--text);
        min-height:100vh;transition:background .3s,color .3s;
    }}
    .container{{max-width:960px;margin:0 auto;padding:32px 20px}}
    header{{
        display:flex;align-items:center;justify-content:space-between;
        flex-wrap:wrap;gap:12px;
        margin-bottom:28px;padding-bottom:14px;
        border-bottom:1px solid var(--border);transition:border-color .3s;
    }}
    header h1{{font-size:22px;font-weight:600}}
    header nav{{display:flex;align-items:center;gap:8px}}
    header nav a{{
        color:var(--accent);text-decoration:none;font-size:13px;
        padding:6px 14px;border:1px solid var(--border);border-radius:6px;
        transition:background .15s,border-color .3s;
    }}
    header nav a:hover{{background:var(--btn-hover-bg)}}
    header nav a.danger{{color:var(--danger);border-color:rgba(248,81,73,.3)}}
    header nav a.danger:hover{{background:rgba(248,81,73,.1)}}
    .theme-toggle{{
        padding:6px 10px;background:var(--card);border:1px solid var(--border);
        border-radius:6px;color:var(--text-secondary);font-size:16px;cursor:pointer;
        line-height:1;transition:background .15s;
    }}
    .theme-toggle:hover{{background:var(--btn-hover-bg)}}
    .section-title{{
        font-size:16px;font-weight:600;margin:28px 0 14px;
        display:flex;align-items:center;gap:8px;
    }}
    .section-title .badge{{font-size:12px;color:var(--text-secondary);font-weight:400}}
    .app-list{{display:flex;flex-direction:column;gap:10px}}
    .app-row{{
        background:var(--card);border:1px solid var(--border);border-radius:10px;
        padding:16px 20px;display:flex;align-items:center;gap:16px;
        transition:border-color .15s,background .3s;
    }}
    .app-row:hover{{border-color:var(--btn-hover-border)}}
    .app-row img{{width:40px;height:40px;object-fit:contain;border-radius:6px;flex-shrink:0}}
    .app-row .info{{flex:1;min-width:0}}
    .app-row .info .name{{font-weight:600;font-size:15px}}
    .app-row .info .meta{{font-size:12px;color:var(--text-secondary);margin-top:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
    .app-row .info .desc{{font-size:12px;color:var(--text-muted);margin-top:1px}}
    .app-row .actions{{display:flex;gap:6px;flex-shrink:0}}
    .app-row .actions button{{
        padding:6px 14px;font-size:12px;border-radius:6px;
        border:1px solid var(--border);background:transparent;color:var(--text);
        cursor:pointer;transition:background .15s,border-color .15s,color .3s;
    }}
    .app-row .actions button:hover{{background:var(--btn-hover-bg);border-color:var(--btn-hover-border)}}
    .app-row .actions button.edit-btn{{color:var(--accent)}}
    .app-row .actions button.del-btn{{color:var(--danger);border-color:rgba(248,81,73,.2)}}
    .app-row .actions button.del-btn:hover{{background:rgba(248,81,73,.1);border-color:var(--danger)}}
    .empty{{text-align:center;padding:48px 20px;color:var(--text-secondary);font-size:14px}}
    .form-panel{{
        background:var(--card);border:1px solid var(--border);border-radius:12px;
        padding:24px;margin-bottom:10px;transition:background .3s,border-color .3s;
    }}
    .form-panel h3{{font-size:15px;font-weight:600;margin-bottom:18px;color:var(--accent)}}
    .form-panel.edit-panel h3{{color:var(--warning)}}
    .form-row{{display:flex;gap:12px;margin-bottom:14px;flex-wrap:wrap}}
    .form-field{{flex:1;min-width:140px}}
    .form-field label{{display:block;font-size:12px;color:var(--text-secondary);margin-bottom:4px;font-weight:500}}
    .form-field input,.form-field textarea{{
        width:100%;padding:8px 12px;
        background:var(--input-bg);border:1px solid var(--border);border-radius:6px;
        color:var(--text);font-size:13px;outline:none;
        font-family:inherit;
        transition:border-color .15s,background .3s,color .3s;
    }}
    .form-field input:focus,.form-field textarea:focus{{border-color:var(--accent)}}
    .form-field textarea{{resize:vertical;min-height:28px}}
    .form-field input[type="file"]{{padding:6px 8px;font-size:12px}}
    .form-field input[type="file"]::file-selector-button{{
        background:var(--btn-hover-bg);color:var(--text);border:1px solid var(--border);
        border-radius:4px;padding:4px 10px;cursor:pointer;margin-right:8px;font-size:11px;
    }}
    .form-field .hint{{font-size:10px;color:var(--text-muted);margin-top:3px}}
    .form-actions{{display:flex;gap:8px;justify-content:flex-end;margin-top:8px}}
    .btn{{padding:8px 22px;border-radius:7px;font-size:13px;font-weight:600;border:none;cursor:pointer;transition:background .15s,transform .15s}}
    .btn:active{{transform:scale(.97)}}
    .btn-primary{{background:var(--btn-primary);color:#fff}}
    .btn-primary:hover{{background:var(--btn-primary-hover)}}
    .btn-cancel{{background:transparent;color:var(--text-secondary);border:1px solid var(--border)}}
    .btn-cancel:hover{{background:var(--btn-hover-bg)}}
    .toast{{position:fixed;top:20px;right:20px;padding:12px 22px;border-radius:8px;font-size:13px;z-index:99;max-width:360px;animation:fadeIn .3s;display:none}}
    .toast.show{{display:block}}
    .toast.success{{background:var(--success);color:#fff}}
    .toast.error{{background:var(--danger-bg);color:#fff}}
    @keyframes fadeIn{{from{{opacity:0;transform:translateY(-8px)}}to{{opacity:1;transform:translateY(0)}}}}
    .hidden{{display:none!important}}
</style>
</head>
<body>
<div class="container">
    <header>
        <h1>{title} <span style="color:var(--text-secondary);font-weight:400;font-size:16px">管理</span></h1>
        <nav>
            <button class="theme-toggle" id="theme-toggle" title="切换主题">☀</button>
            <a href="/">仪表盘</a>
            <a href="/logout" class="danger">退出</a>
        </nav>
    </header>

    <div id="toast" class="toast"></div>

    <!-- 应用列表 -->
    <div class="section-title">已配置的应用 <span class="badge">({app_count})</span></div>
    <div class="app-list">
        {app_rows}
    </div>
    {empty_hint}

    <!-- 添加表单 -->
    <div class="section-title" style="margin-top:36px">添加新应用</div>
    <form class="form-panel" method="post" action="/manage/add" enctype="multipart/form-data">
        <h3>+ 新建应用</h3>
        <div class="form-row">
            <div class="form-field">
                <label>应用名称 *</label>
                <input type="text" name="name" placeholder="例如：Grafana 监控" required autocomplete="off">
            </div>
            <div class="form-field">
                <label>应用 ID *</label>
                <input type="text" name="id" placeholder="例如：grafana" required pattern="[a-zA-Z0-9_-]+" autocomplete="off">
                <span class="hint">URL 标识，仅允许英文/数字/连字符</span>
            </div>
        </div>
        <div class="form-row">
            <div class="form-field" style="flex:2">
                <label>后端地址 *</label>
                <input type="text" name="url" placeholder="http://127.0.0.1:3000" required autocomplete="off">
            </div>
            <div class="form-field">
                <label>图标文件</label>
                <input type="file" name="icon_file" accept="image/svg+xml,image/png,image/jpeg,image/webp,image/x-icon">
                <span class="hint">不选则使用默认图标</span>
            </div>
        </div>
        <div class="form-row">
            <div class="form-field">
                <label>描述（可选）</label>
                <input type="text" name="description" placeholder="简要说明" autocomplete="off">
            </div>
        </div>
        <div class="form-actions">
            <button type="submit" class="btn btn-primary">添加应用</button>
        </div>
    </form>
</div>

<script>
const toastEl = document.getElementById('toast');
function showToast(msg, type) {{
    toastEl.textContent = msg;
    toastEl.className = 'toast show ' + type;
    setTimeout(function() {{ toastEl.classList.remove('show'); }}, 3000);
}}

document.querySelectorAll('.del-btn').forEach(function(btn) {{
    btn.addEventListener('click', function() {{
        var appId = this.getAttribute('data-id');
        var appName = this.getAttribute('data-name');
        if (!confirm('确定要删除 "' + appName + '" 吗？此操作不可撤销。')) return;
        var form = document.getElementById('del-form-' + appId);
        form.submit();
    }});
}});

var editingAppId = null;
document.querySelectorAll('.edit-btn').forEach(function(btn) {{
    btn.addEventListener('click', function() {{
        var appId = this.getAttribute('data-id');
        if (editingAppId && editingAppId !== appId) {{
            cancelEdit(editingAppId);
        }}
        editingAppId = appId;
        document.getElementById('edit-panel-' + appId).classList.remove('hidden');
        document.getElementById('view-row-' + appId).classList.add('hidden');
    }});
}});

function cancelEdit(appId) {{
    document.getElementById('edit-panel-' + appId).classList.add('hidden');
    document.getElementById('view-row-' + appId).classList.remove('hidden');
    if (editingAppId === appId) editingAppId = null;
}}

{toast_script}
(function(){{var t=localStorage.getItem('theme')||'dark';document.documentElement.setAttribute('data-theme',t);
var b=document.getElementById('theme-toggle');if(b){{b.textContent=t==='light'?'🌙':'☀';}}
b.addEventListener('click',function(){{var n=document.documentElement.getAttribute('data-theme')==='light'?'dark':'light';
document.documentElement.setAttribute('data-theme',n);localStorage.setItem('theme',n);b.textContent=n==='light'?'🌙':'☀';}});}})();
</script>
</body>
</html>"""

_ALLOWED_ICON_TYPES = {
    "image/svg+xml": ".svg",
    "image/png": ".png",
    "image/jpeg": ".jpg",
    "image/webp": ".webp",
    "image/x-icon": ".ico",
}


def _render_manage(toast: str = "", toast_type: str = "success") -> str:
    """渲染管理页面。"""
    rows: list[str] = []
    for app in CONFIG.apps:
        desc_html = f'<span class="desc">{app.description}</span>' if app.description else ""
        row = (
            f'<div class="app-row" id="view-row-{app.id}">'
            f'<img src="{app.icon}" alt="" onerror="this.style.display=\'none\'">'
            f'<div class="info">'
            f'<div class="name">{app.name}</div>'
            f'<div class="meta">ID: {app.id} &nbsp;|&nbsp; {app.url}</div>'
            f'{desc_html}'
            f'</div>'
            f'<div class="actions">'
            f'<button class="edit-btn" data-id="{app.id}">编辑</button>'
            f'<button class="del-btn" data-id="{app.id}" data-name="{app.name}">删除</button>'
            f'</div>'
            f'</div>'
            f'<form id="del-form-{app.id}" method="post" action="/manage/delete/{app.id}" class="hidden"></form>'
        )
        # Edit panel for this app
        edit_panel = (
            f'<form class="form-panel edit-panel hidden" id="edit-panel-{app.id}" '
            f'method="post" action="/manage/edit/{app.id}" enctype="multipart/form-data">'
            f'<h3>编辑: {app.name}</h3>'
            f'<div class="form-row">'
            f'<div class="form-field">'
            f'<label>应用名称 *</label>'
            f'<input type="text" name="name" value="{app.name}" required>'
            f'</div>'
            f'<div class="form-field">'
            f'<label>应用 ID</label>'
            f'<input type="text" value="{app.id}" disabled>'
            f'<span class="hint">ID 不可修改</span>'
            f'</div>'
            f'</div>'
            f'<div class="form-row">'
            f'<div class="form-field" style="flex:2">'
            f'<label>后端地址 *</label>'
            f'<input type="text" name="url" value="{app.url}" required>'
            f'</div>'
            f'<div class="form-field">'
            f'<label>替换图标</label>'
            f'<input type="file" name="icon_file" accept="image/svg+xml,image/png,image/jpeg,image/webp,image/x-icon">'
            f'<span class="hint">留空则保持现有图标</span>'
            f'</div>'
            f'</div>'
            f'<div class="form-row">'
            f'<div class="form-field">'
            f'<label>描述</label>'
            f'<input type="text" name="description" value="{app.description or ""}">'
            f'</div>'
            f'</div>'
            f'<div class="form-actions">'
            f'<button type="button" class="btn btn-cancel" onclick="cancelEdit(\'{app.id}\')">取消</button>'
            f'<button type="submit" class="btn btn-primary">保存</button>'
            f'</div>'
            f'</form>'
        )
        rows.append(row + edit_panel)

    empty_hint = ""
    if not rows:
        empty_hint = '<div class="empty">暂无应用，使用下方表单添加第一个</div>'

    toast_script = ""
    if toast:
        toast_script = f'showToast("{toast}", "{toast_type}");'

    return _MANAGE_HTML.format(
        title=CONFIG.title,
        app_count=len(CONFIG.apps),
        app_rows="\n        ".join(rows) if rows else "",
        empty_hint=empty_hint,
        toast_script=toast_script,
    )


# ═══════════════════════════════════════════════════════════════
#  错误页面 HTML
# ═══════════════════════════════════════════════════════════════
_ERROR_HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>{title}</title>
<style>
    :root{{--bg:#0d1117;--card:#161b22;--border:#30363d;--text:#e6edf3;
        --text-secondary:#7d8590;--text-muted:#484f58;--accent:#58a6ff;
        --btn-primary:#238636;--btn-primary-hover:#2ea043;}}
    [data-theme="light"]{{--bg:#f6f8fa;--card:#fff;--border:#d0d7de;--text:#1f2328;
        --text-secondary:#656d76;--text-muted:#8b949e;--accent:#0969da;
        --btn-primary:#1f883d;--btn-primary-hover:#1a7f37;}}
    *,*::before,*::after{{margin:0;padding:0;box-sizing:border-box}}
    body{{
        font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,"Noto Sans SC",sans-serif;
        background:var(--bg);color:var(--text);
        min-height:100vh;display:flex;align-items:center;justify-content:center;
        text-align:center;transition:background .3s,color .3s;
    }}
    .card{{
        background:var(--card);border:1px solid var(--border);border-radius:12px;
        padding:40px 36px;width:480px;max-width:92vw;transition:background .3s,border-color .3s;
    }}
    .code{{font-size:64px;font-weight:700;color:{code_color};margin-bottom:8px}}
    h1{{font-size:20px;font-weight:600;margin-bottom:8px}}
    p{{color:var(--text-secondary);margin-bottom:6px;font-size:14px}}
    pre{{color:var(--text-muted);font-size:12px;margin:8px 0;word-break:break-all}}
    a{{display:inline-block;margin-top:16px;padding:10px 24px;
       background:var(--btn-primary);color:#fff;border-radius:8px;text-decoration:none;
       font-size:14px;font-weight:600;transition:background .15s}}
    a:hover{{background:var(--btn-primary-hover)}}
    .theme-toggle{{
        position:fixed;top:16px;right:16px;padding:6px 10px;
        background:var(--card);border:1px solid var(--border);border-radius:6px;
        color:var(--text-secondary);font-size:18px;cursor:pointer;
        line-height:1;transition:background .15s;
    }}
    .theme-toggle:hover{{background:rgba(128,128,128,.15)}}
</style>
</head>
<body>
<div class="card">
    <div class="code">{status_code}</div>
    <h1>{heading}</h1>
    <p>{message}</p>
    {extra}
    <a href="{back_url}">{back_text}</a>
</div>
<button class="theme-toggle" id="theme-toggle" title="切换主题">☀</button>
<script>
(function(){{var t=localStorage.getItem('theme')||'dark';document.documentElement.setAttribute('data-theme',t);
var b=document.getElementById('theme-toggle');b.textContent=t==='light'?'🌙':'☀';
b.addEventListener('click',function(){{var n=document.documentElement.getAttribute('data-theme')==='light'?'dark':'light';
document.documentElement.setAttribute('data-theme',n);localStorage.setItem('theme',n);b.textContent=n==='light'?'🌙':'☀';}});}})();
</script>
</body>
</html>"""


def _render_error(status: int, heading: str, message: str, extra: str = "") -> str:
    """渲染错误页面。"""
    colors = {502: "#f0883e", 504: "#f0883e", 404: "#58a6ff", 500: "#f85149"}
    return _ERROR_HTML.format(
        title=f"{status} - {heading}",
        status_code=status,
        heading=heading,
        message=message,
        extra=extra,
        code_color=colors.get(status, "#f85149"),
        back_url="/dashboard",
        back_text="返回仪表盘",
    )


# ═══════════════════════════════════════════════════════════════
#  Base 标签注入
# ═══════════════════════════════════════════════════════════════
# 不应注入 <base> 标签的静态资源后缀
_SKIP_INJECT_SUFFIXES = frozenset({
    ".js", ".mjs", ".cjs", ".css", ".json", ".xml", ".wasm",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".map", ".webmanifest", ".txt", ".md",
    ".mp3", ".mp4", ".webm", ".ogg", ".avi",
})


def _should_inject(path: str) -> bool:
    """判断是否应对该路径的 HTML 响应注入 <base> 标签。

    跳过明确的静态资源请求（按后缀判断），避免 SPA 后端对不存在
    的静态资源返回 HTML fallback 时，我们把 HTML 注入 JS/CSS 响应导致破坏。
    """
    if not path:
        return True
    # 取最后一段路径（文件名部分）
    last_segment = path.rsplit("/", 1)[-1]
    # 检查文件后缀
    for suffix in _SKIP_INJECT_SUFFIXES:
        if last_segment.lower().endswith(suffix):
            return False
    return True


def _inject_base_tag(html_body: bytes, base_href: str) -> bytes:
    """在 HTML 响应的 <head> 后注入 <base href="..."> 标签。

    这使得被代理页面中的相对 URL (如 ./style.css, ../api)
    能正确解析到 /p/<app-id>/ 路径下。

    注意：仅影响相对路径，绝对路径 (如 /static/app.js) 不受 base 标签影响。
    """
    injection = f'<base href="{base_href}">'.encode("utf-8")

    # 尝试在 <head> 后注入
    idx = html_body.lower().find(b"<head>")
    if idx >= 0:
        idx += len(b"<head>")
        return html_body[:idx] + injection + html_body[idx:]

    # 尝试 <head 属性...> 的情况
    idx = html_body.lower().find(b"<head")
    if idx >= 0:
        close = html_body.find(b">", idx)
        if close >= 0:
            return html_body[:close + 1] + injection + html_body[close + 1:]

    # 尝试在 <html> 后插入一个 <head>
    idx = html_body.lower().find(b"<html>")
    if idx >= 0:
        idx += len(b"<html>")
        return html_body[:idx] + b"<head>" + injection + b"</head>" + html_body[idx:]

    # 无法识别，原样返回
    return html_body


# ═══════════════════════════════════════════════════════════════
#  中间件 — 鉴权门
# ═══════════════════════════════════════════════════════════════
@web.middleware
async def auth_middleware(request: web.Request, handler) -> web.StreamResponse:
    # 公开路径 (无需登录)
    public_paths = {"/login", "/logout"}

    if request.path in public_paths:
        return await handler(request)

    if _valid(request.cookies.get(COOKIE_NAME)):
        return await handler(request)

    # 未登录：API 风格请求返回 401 JSON，浏览器请求重定向到登录页
    if (
        request.headers.get("Accept") == "application/json"
        or request.headers.get("X-Requested-With") == "XMLHttpRequest"
        or request.path.startswith("/api/")
    ):
        return web.json_response({"error": "Unauthorized"}, status=401)

    next_url = request.path_qs
    return web.HTTPFound(f"/login?next={next_url}")


# ═══════════════════════════════════════════════════════════════
#  路由处理
# ═══════════════════════════════════════════════════════════════
async def login_page(request: web.Request) -> web.Response:
    """GET /login"""
    next_url = request.query.get("next", "")
    return web.Response(
        text=_render_login(error=False, next_url=next_url),
        content_type="text/html", charset="utf-8",
    )


async def login_action(request: web.Request) -> web.Response:
    """POST /login"""
    try:
        data = await request.post()
        password = data.get("password", "")
    except Exception:
        password = ""

    if password == CONFIG.auth_password:
        token = _new_session()
        next_url = request.query.get("next", "")
        # 确定默认跳转目标
        if not next_url or not next_url.startswith("/") or next_url.startswith("//"):
            next_url = "/dashboard"

        resp = web.HTTPFound(next_url)
        resp.set_cookie(
            COOKIE_NAME,
            token,
            max_age=CONFIG.session_timeout,
            httponly=True,
            secure=False,
            samesite="Lax",
        )
        return resp

    # 密码错误：回到登录页并显示错误
    next_url = request.query.get("next", "")
    return web.Response(
        text=_render_login(error=True, next_url=next_url),
        content_type="text/html", charset="utf-8",
        status=401,
    )


async def logout(request: web.Request) -> web.Response:
    """GET /logout"""
    token = request.cookies.get(COOKIE_NAME)
    if token:
        _sessions.pop(token, None)
    resp = web.HTTPFound("/login")
    resp.del_cookie(COOKIE_NAME)
    return resp


async def dashboard_page(request: web.Request) -> web.Response:
    """GET / — 仪表盘首页；WebSocket 升级 → 兜底代理。"""
    if _is_websocket(request):
        return await catch_all_proxy(request)
    return web.Response(
        text=_render_dashboard(),
        content_type="text/html", charset="utf-8",
    )


# ═══════════════════════════════════════════════════════════════
#  管理面板路由
# ═══════════════════════════════════════════════════════════════

def _icon_path_for(app_id: str, ext: str) -> str:
    """生成图标文件路径。"""
    icons_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "icons")
    return os.path.join(icons_dir, f"{app_id}{ext}")


async def manage_page(request: web.Request) -> web.Response:
    """GET /manage — 管理页面。"""
    return web.Response(
        text=_render_manage(),
        content_type="text/html", charset="utf-8",
    )


async def manage_add(request: web.Request) -> web.Response:
    """POST /manage/add — 添加应用。"""
    try:
        data = await request.post()
        name = (data.get("name", "") or "").strip()
        app_id = (data.get("id", "") or "").strip()
        url = (data.get("url", "") or "").strip()
        description = (data.get("description", "") or "").strip()
        icon_file = data.get("icon_file", None)
    except Exception:
        return web.Response(
            text=_render_manage(toast="表单解析失败", toast_type="error"),
            content_type="text/html", charset="utf-8",
            status=400,
        )

    # 验证
    if not name or not app_id or not url:
        return web.Response(
            text=_render_manage(toast="名称、ID、地址不能为空", toast_type="error"),
            content_type="text/html", charset="utf-8",
            status=400,
        )

    if CONFIG.get_app(app_id):
        return web.Response(
            text=_render_manage(toast=f"ID '{app_id}' 已存在", toast_type="error"),
            content_type="text/html", charset="utf-8",
            status=409,
        )

    # 处理图标
    icon = "/icons/default.svg"
    if icon_file and hasattr(icon_file, "content_type"):
        ext = _ALLOWED_ICON_TYPES.get(icon_file.content_type)
        if ext:
            dst = _icon_path_for(app_id, ext)
            with open(dst, "wb") as f:
                f.write(icon_file.file.read())
            icon = f"/icons/{app_id}{ext}"

    # 添加
    new_app = ProxyApp(id=app_id, name=name, url=url.rstrip("/"), icon=icon, description=description)
    CONFIG.apps.append(new_app)
    save_config()

    return web.HTTPFound("/manage")


async def manage_edit(request: web.Request) -> web.Response:
    """POST /manage/edit/{app_id} — 编辑应用。"""
    app_id = request.match_info["app_id"]
    app = CONFIG.get_app(app_id)
    if app is None:
        return web.Response(
            text=_render_manage(toast="应用不存在", toast_type="error"),
            content_type="text/html", charset="utf-8",
            status=404,
        )

    try:
        data = await request.post()
        name = (data.get("name", "") or "").strip()
        url = (data.get("url", "") or "").strip()
        description = (data.get("description", "") or "").strip()
        icon_file = data.get("icon_file", None)
    except Exception:
        return web.Response(
            text=_render_manage(toast="表单解析失败", toast_type="error"),
            content_type="text/html", charset="utf-8",
            status=400,
        )

    if not name or not url:
        return web.Response(
            text=_render_manage(toast="名称和地址不能为空", toast_type="error"),
            content_type="text/html", charset="utf-8",
            status=400,
        )

    app.name = name
    app.url = url.rstrip("/")
    app.description = description

    # 处理图标替换
    if icon_file and hasattr(icon_file, "content_type"):
        ext = _ALLOWED_ICON_TYPES.get(icon_file.content_type)
        if ext:
            # 删除旧图标
            _remove_icon_file(app.icon)
            dst = _icon_path_for(app_id, ext)
            with open(dst, "wb") as f:
                f.write(icon_file.file.read())
            app.icon = f"/icons/{app_id}{ext}"

    save_config()
    return web.HTTPFound("/manage")


async def manage_delete(request: web.Request) -> web.Response:
    """POST /manage/delete/{app_id} — 删除应用。"""
    app_id = request.match_info["app_id"]
    app = CONFIG.get_app(app_id)
    if app is None:
        return web.HTTPFound("/manage")

    # 删除图标文件
    _remove_icon_file(app.icon)
    CONFIG.apps.remove(app)
    save_config()
    return web.HTTPFound("/manage")


def _remove_icon_file(icon: str) -> None:
    """删除图标文件（仅删除 /icons/ 下的本地文件，跳过外部 URL）。"""
    if not icon.startswith("/icons/"):
        return
    filename = icon.split("/")[-1]
    if filename == "default.svg":
        return  # 不删除默认图标
    icons_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "icons")
    filepath = os.path.join(icons_dir, filename)
    try:
        os.remove(filepath)
    except OSError:
        pass


# ═══════════════════════════════════════════════════════════════
#  代理核心 — HTTP + WebSocket
# ═══════════════════════════════════════════════════════════════
_HOP_BY_HOP_REQ = frozenset({
    "connection", "keep-alive", "proxy-authenticate",
    "proxy-authorization", "te", "trailers", "transfer-encoding",
    "upgrade",
})
_HOP_BY_HOP_RES = frozenset({
    "transfer-encoding", "content-encoding", "content-length",
})


def _is_websocket(request: web.Request) -> bool:
    return (
        request.headers.get("Upgrade", "").lower() == "websocket"
        and "upgrade" in request.headers.get("Connection", "").lower()
    )


async def proxy_app(request: web.Request) -> web.StreamResponse:
    """多应用代理：/p/{app_id}/{tail:.*}"""
    _cleanup()

    app_id = request.match_info["app_id"]
    tail = request.match_info.get("tail", "")

    app = CONFIG.get_app(app_id)
    if app is None:
        return web.Response(
            text=_render_error(404, "应用未找到",
                f"未知的应用标识：{app_id}",
                extra=f'<pre>可用应用：{", ".join(a.id for a in CONFIG.apps)}</pre>'),
            content_type="text/html", charset="utf-8",
            status=404,
        )

    if _is_websocket(request):
        resp = await _proxy_ws(request, app.url, tail)
    else:
        resp = await _proxy_http(request, app.url, tail, app_id)

    # 设置上下文 Cookie，使得后端应用的绝对路径请求能被兜底路由正确代理
    if isinstance(resp, web.StreamResponse) and not isinstance(resp, web.WebSocketResponse):
        resp.set_cookie(
            PROXY_APP_COOKIE, app_id,
            max_age=CONFIG.session_timeout,
            httponly=True, secure=False, samesite="Lax",
        )
    return resp


async def _proxy_http(
    request: web.Request,
    app_url: str,
    tail: str,
    app_id: str | None,
) -> web.StreamResponse:
    """HTTP 反向代理到指定后端。"""
    # 构建目标 URL
    target = f"{app_url}/{tail.lstrip('/')}"
    if request.query_string:
        target = f"{target}?{request.query_string}"

    body = await request.read()

    # 组装转发请求头
    headers: dict[str, str] = {}
    for name, value in request.headers.items():
        low = name.lower()
        if low in _HOP_BY_HOP_REQ or low == "host":
            continue
        # 剥离 Origin / Referer：后端看到代理地址会触发 CSRF 拦截 (422)
        if low in ("origin", "referer"):
            continue
        headers[name] = value

    backend_host = app_url.split("://", 1)[1].split("/", 1)[0]
    headers["Host"] = backend_host
    # 不暴露代理地址和客户端 IP 给后端，避免触发后端的 IP/域名安全检查
    headers["X-Forwarded-For"] = "127.0.0.1"
    headers["X-Forwarded-Host"] = backend_host
    headers["X-Forwarded-Proto"] = request.scheme

    try:
        async with ClientSession(timeout=ClientTimeout(total=300)) as sess:
            async with sess.request(
                method=request.method,
                url=target,
                headers=headers,
                data=body,
                allow_redirects=False,
            ) as resp:
                resp_body = await resp.read()

                # 对 HTML 响应注入 <base> 标签（跳过静态资源）
                content_type = resp.headers.get("Content-Type", "")
                if app_id and content_type.lower().startswith("text/html") and _should_inject(tail):
                    resp_body = _inject_base_tag(resp_body, f"/p/{app_id}/")

                resp_headers = {
                    n: v for n, v in resp.headers.items()
                    if n.lower() not in _HOP_BY_HOP_RES
                }

                # 重写后端返回的 Location 头，避免重定向到代理根路径
                if app_id and resp.status in (301, 302, 303, 307, 308):
                    location = resp_headers.get("Location", "")
                    if location.startswith("/") and not location.startswith("//"):
                        resp_headers["Location"] = f"/p/{app_id}{location}"

                return web.Response(
                    body=resp_body,
                    status=resp.status,
                    headers=resp_headers,
                )
    except ClientError as exc:
        return web.Response(
            text=_render_error(502, "网关错误",
                "无法连接到后端服务", extra=f"<pre>{exc}</pre>"),
            content_type="text/html", charset="utf-8",
            status=502,
        )
    except asyncio.TimeoutError:
        return web.Response(
            text=_render_error(504, "网关超时",
                "后端服务响应超时"),
            content_type="text/html", charset="utf-8",
            status=504,
        )


async def _proxy_ws(
    request: web.Request,
    app_url: str,
    tail: str,
) -> web.StreamResponse:
    """WebSocket 双向代理到指定后端。"""
    target = (
        app_url
        .replace("http://", "ws://")
        .replace("https://", "wss://")
    )
    if tail:
        target = f"{target.rstrip('/')}/{tail.lstrip('/')}"
    if request.query_string:
        target = f"{target}?{request.query_string}"

    ws_client = web.WebSocketResponse()
    await ws_client.prepare(request)

    try:
        async with ClientSession() as sess:
            ws_headers = {
                n: v for n, v in request.headers.items()
                if n.lower() not in (
                    "host", "origin",
                    "sec-websocket-key", "sec-websocket-version",
                    "sec-websocket-extensions", "connection", "upgrade",
                )
            } or None

            async with sess.ws_connect(target, headers=ws_headers) as ws_backend:

                async def c2s():
                    """客户端 -> 服务端"""
                    async for msg in ws_client:
                        if msg.type == WSMsgType.TEXT:
                            await ws_backend.send_str(msg.data)
                        elif msg.type == WSMsgType.BINARY:
                            await ws_backend.send_bytes(msg.data)
                        elif msg.type in (WSMsgType.CLOSE, WSMsgType.ERROR):
                            break

                async def s2c():
                    """服务端 -> 客户端"""
                    async for msg in ws_backend:
                        if msg.type == WSMsgType.TEXT:
                            await ws_client.send_str(msg.data)
                        elif msg.type == WSMsgType.BINARY:
                            await ws_client.send_bytes(msg.data)
                        elif msg.type in (WSMsgType.CLOSE, WSMsgType.ERROR):
                            break

                await asyncio.gather(c2s(), s2c(), return_exceptions=True)

    except Exception:
        pass
    finally:
        if not ws_client.closed:
            await ws_client.close()

    return ws_client


# ═══════════════════════════════════════════════════════════════
#  兜底代理 — 处理被代理应用的绝对路径请求
# ═══════════════════════════════════════════════════════════════

async def catch_all_proxy(request: web.Request) -> web.StreamResponse:
    """兜底路由 — 根据 proxy_app Cookie 将请求代理到正确的后端。

    解决 SPA 应用 (code-server, Home Assistant, CasaOS 等) 使用绝对路径
    (如 /static/app.js, /api/data) 请求资源时的问题。
    """
    _cleanup()

    app_id = request.cookies.get(PROXY_APP_COOKIE, "")
    tail = request.match_info.get("tail", "")

    app = CONFIG.get_app(app_id) if app_id else None
    if app is None:
        return web.Response(
            text=_render_error(404, "未找到上下文",
                "请从仪表盘进入应用后再访问此页面",
                extra=f'<pre>Cookie proxy_app: {app_id or "(未设置)"}</pre>'),
            content_type="text/html", charset="utf-8",
            status=404,
        )

    if _is_websocket(request):
        return await _proxy_ws(request, app.url, tail)

    return await _proxy_http(request, app.url, tail, app_id)


# ═══════════════════════════════════════════════════════════════
#  应用组装 & 入口
# ═══════════════════════════════════════════════════════════════
def create_app() -> web.Application:
    global CONFIG
    CONFIG = load_config()

    app = web.Application(middlewares=[auth_middleware])

    # 始终注册的路由
    app.router.add_get("/login", login_page)
    app.router.add_post("/login", login_action)
    app.router.add_get("/logout", logout)

    # 静态文件 — 图标目录
    _ensure_icons_dir()
    app.router.add_static("/icons/", path="icons/", name="icons")
    # 仪表盘 — 根路径即为仪表盘
    app.router.add_get("/", dashboard_page)
    # 兼容旧的 /dashboard 显式路径
    app.router.add_get("/dashboard", dashboard_page)
    # 管理面板
    app.router.add_get("/manage", manage_page)
    app.router.add_post("/manage/add", manage_add)
    app.router.add_post("/manage/edit/{app_id}", manage_edit)
    app.router.add_post("/manage/delete/{app_id}", manage_delete)
    # 多应用代理路由
    app.router.add_route("*", "/p/{app_id}/{tail:.*}", proxy_app)
    # 无尾随路径也匹配（/p/<app-id> 或 /p/<app-id>/）
    app.router.add_route("*", "/p/{app_id}", lambda r: web.HTTPFound(f"/p/{r.match_info['app_id']}/"))
    # /p/ 无 app_id → 返回仪表盘
    app.router.add_route("*", "/p", lambda r: web.HTTPFound("/"))
    app.router.add_route("*", "/p/", lambda r: web.HTTPFound("/"))
    # 兜底代理 — 捕获被代理应用的绝对路径请求 (必须在所有路由之后)
    app.router.add_route("*", "/{tail:.*}", catch_all_proxy)

    return app


def main() -> None:
    # 先加载配置以显示启动信息
    global CONFIG
    CONFIG = load_config()

    pwd_note = ""
    if CONFIG.auth_password == "admin":
        pwd_note = "  <-- 默认密码! 请修改 proxy_config.json 中的 auth_password"
    elif CONFIG.auth_password == "Xjj20030715#":
        pwd_note = "  <-- 请修改 proxy_config.json 中的密码"

    apps_lines = "\n".join(
        f"    {app.id:20s} -> {app.url}" for app in CONFIG.apps
    )
    print(f"""
============================================================
  Auth Proxy Bridge
------------------------------------------------------------
  监听地址 : {CONFIG.listen_host}:{CONFIG.listen_port}
  登录密码 : ***{pwd_note}
  会话超时 : {CONFIG.session_timeout}s ({CONFIG.session_timeout // 3600}h)
  应用数量 : {len(CONFIG.apps)}
------------------------------------------------------------
{apps_lines}
============================================================
""")

    app = create_app()
    runner = web.AppRunner(app)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    async def _start():
        await runner.setup()
        # IPv4
        site_v4 = web.TCPSite(runner, CONFIG.listen_host, CONFIG.listen_port)
        await site_v4.start()
        # IPv6 (双栈)
        try:
            site_v6 = web.TCPSite(runner, "::", CONFIG.listen_port)
            await site_v6.start()
        except OSError:
            print("[warn] IPv6 不可用，仅监听 IPv4")

    try:
        loop.run_until_complete(_start())
        loop.run_forever()
    except KeyboardInterrupt:
        print("\n[info] 收到中断信号，正在退出...")
    finally:
        loop.run_until_complete(runner.cleanup())
        loop.close()


if __name__ == "__main__":
    main()
