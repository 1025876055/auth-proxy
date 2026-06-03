# Auth Proxy Bridge

为没有鉴权的本地 Web 服务添加密码保护的反向代理。全平台通用 (Windows / Linux / macOS)。

---

[English](#english)

## 中文

### 简介

Auth Proxy Bridge 是一个轻量级反向代理，为内网中那些没有自带登录鉴权的 Web 服务（如文件管理器、监控面板、数据库管理工具等）添加统一的密码保护。

**核心功能：**

- **密码登录** — 所有服务共享一个登录入口，输入密码后获得会话
- **多应用仪表盘** — 登录后展示所有配置的内网服务，点击卡片即可访问
- **弹性布局** — 仪表盘使用 CSS Grid 自适应排列，手机/平板/桌面均可使用
- **路径代理** — 每个应用通过 `/p/<app-id>/` 代理访问，自动注入 `<base>` 标签修正相对路径
- **WebSocket 支持** — 完整支持 WebSocket 双向代理
- **配置文件驱动** — 通过 `proxy_config.json` 灵活定义应用名称、图标、端口

### 快速开始

```bash
# 安装依赖（仅需 aiohttp）
pip install -r requirements.txt

# 启动
python auth_proxy.py
```

浏览器打开 `http://127.0.0.1:8888`，输入密码即可进入仪表盘。

### 后台运行

```bash
# Linux / macOS
nohup python auth_proxy.py > /dev/null 2>&1 &

# 或使用 systemd
# 参见下方 systemd 示例

# Windows
# 推荐使用 NSSM (Non-Sucking Service Manager) 注册为服务
```

### 配置

```json
{
    "listen_host": "0.0.0.0",
    "listen_port": 8888,
    "auth_password": "your-password-here",
    "session_timeout": 86400,
    "title": "内网服务导航",
    "apps": [
        {
            "id": "files",
            "name": "文件管理器",
            "url": "http://127.0.0.1:8765",
            "icon": "/icons/files.svg",
            "description": "内网文件管理服务"
        },
        {
            "id": "monitor",
            "name": "监控面板",
            "url": "http://127.0.0.1:9090",
            "icon": "/icons/monitor.svg",
            "description": "系统资源监控面板"
        }
    ]
}
```

**配置字段说明：**

| 字段 | 类型 | 必填 | 默认值 | 说明 |
|---|---|---|---|---|
| `listen_host` | string | 否 | `0.0.0.0` | 监听地址 |
| `listen_port` | int | 否 | `8888` | 监听端口 |
| `auth_password` | string | 否 | `admin` | 登录密码，建议修改 |
| `session_timeout` | int | 否 | `86400` | 会话超时秒数 |
| `title` | string | 否 | `Proxy Bridge` | 页面标题 |
| `apps` | array | 是 | - | 应用列表 |

**apps 数组字段：**

| 字段 | 类型 | 必填 | 默认值 | 说明 |
|---|---|---|---|---|
| `id` | string | 是 | - | 应用标识，用于 URL 路由 |
| `name` | string | 是 | - | 显示名称 |
| `url` | string | 是 | - | 后端地址，如 `http://127.0.0.1:8765` |
| `icon` | string | 否 | `/icons/default.svg` | 图标路径，可用本地路径或完整 URL |
| `description` | string | 否 | - | 应用简介 |

**图标说明：**

`icon` 字段支持：
- **本地路径**：如 `/icons/files.svg` — 放在 `icons/` 目录中的文件，由代理自动托管
- **外部 URL**：如 `https://cdn.example.com/icon.png` — 直接引用远程图标
- 支持 SVG、PNG、JPG 等常用图片格式
- 若图标加载失败，自动显示默认图标

### systemd 服务 (Linux)

```ini
# /etc/systemd/system/auth-proxy.service
[Unit]
Description=Auth Proxy Bridge
After=network.target

[Service]
Type=simple
User=your-user
WorkingDirectory=/path/to/auth-proxy
ExecStart=/usr/bin/python3 auth_proxy.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now auth-proxy
```

### Docker

```dockerfile
FROM python:3.11-alpine
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 8888
CMD ["python", "auth_proxy.py"]
```

---

## English

### Overview

Auth Proxy Bridge is a lightweight reverse proxy that adds password authentication to internal web services that lack built-in login (file managers, monitoring dashboards, database admin tools, etc.).

**Key Features:**

- **Password Auth** — Single login portal protecting all configured services
- **Multi-app Dashboard** — Responsive card-based dashboard for selecting services after login
- **Flexible Layout** — CSS Grid auto-fit cards, works on mobile/tablet/desktop
- **Path-based Proxy** — Each app at `/p/<app-id>/`, with automatic `<base>` tag injection for relative URLs
- **WebSocket Support** — Full bidirectional WebSocket proxying
- **Config-driven** — Define apps, names, icons, and ports via `proxy_config.json`

### Quick Start

```bash
# Install (only requires aiohttp)
pip install -r requirements.txt

# Run
python auth_proxy.py
```

Open `http://127.0.0.1:8888` in a browser, enter the password.

### Background / Service

```bash
# Linux / macOS
nohup python auth_proxy.py > /dev/null 2>&1 &

# systemd — see example below

# Windows
# Use NSSM or Task Scheduler to run as a service
```

### Configuration

```json
{
    "listen_host": "0.0.0.0",
    "listen_port": 8888,
    "auth_password": "change-me",
    "session_timeout": 86400,
    "title": "Internal Services",
    "apps": [
        {
            "id": "grafana",
            "name": "Grafana",
            "url": "http://127.0.0.1:3000",
            "icon": "/icons/grafana.svg",
            "description": "Monitoring dashboards"
        },
        {
            "id": "jenkins",
            "name": "Jenkins",
            "url": "http://127.0.0.1:8080",
            "icon": "https://cdn.example.com/jenkins.png",
            "description": "CI/CD pipeline"
        }
    ]
}
```

**Top-level fields:**

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `listen_host` | string | No | `0.0.0.0` | Listen address |
| `listen_port` | int | No | `8888` | Listen port |
| `auth_password` | string | No | `admin` | Login password |
| `session_timeout` | int | No | `86400` | Session timeout in seconds |
| `title` | string | No | `Proxy Bridge` | Page title |
| `apps` | array | Yes | - | App definitions |

**Per-app fields:**

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `id` | string | Yes | - | URL-safe identifier for routing |
| `name` | string | Yes | - | Display name |
| `url` | string | Yes | - | Backend URL, e.g. `http://127.0.0.1:3000` |
| `icon` | string | No | `/icons/default.svg` | Icon path — local path or full URL |
| `description` | string | No | - | Short description |

**Icons:**

The `icon` field accepts:
- **Local paths**: `/icons/my-app.svg` — files in the `icons/` directory, hosted by the proxy
- **External URLs**: `https://cdn.example.com/icon.png` — remote icons
- SVG, PNG, JPG formats supported
- Falls back to a default icon on load failure

### systemd Service

```ini
# /etc/systemd/system/auth-proxy.service
[Unit]
Description=Auth Proxy Bridge
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/opt/auth-proxy
ExecStart=/usr/bin/python3 auth_proxy.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### Docker

```dockerfile
FROM python:3.11-alpine
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 8888
CMD ["python", "auth_proxy.py"]
```

### License

MIT
