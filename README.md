# ForensicsToolkits 部署指南

本项目提供两种推荐部署方式：

- 源码部署：适合本地开发、Windows 本机调试、需要直接访问本机 Hashcat/CyberChef 目录的场景
- Docker 部署：适合 Linux 服务器、本地容器化运行、需要统一前后端启动流程的场景

当前项目已经切换为 Hashcat 外部目录方案：

- Windows 源码部署使用本机目录
- Docker 部署使用宿主机目录挂载到容器

## 目录说明

项目中和部署相关的核心文件：

- `docker-compose.yml`：本地构建并启动前后端容器
- `.env.example`：Docker 部署主配置模板
- `backend/.env.example`：源码部署时后端本地覆盖模板
- `deploy.sh`：构建并推送前后端镜像
- `frontend/Dockerfile`：前端镜像构建文件
- `backend/Dockerfile`：后端镜像构建文件

运行数据默认保存在以下目录：

- Docker 部署默认保存在 `./docker-data/backend/`
- 源码部署默认保存在 `backend/storage/` 或由环境变量指定的目录

## 环境要求

### 源码部署

- Python 3.11
- Node.js 20+
- npm
- Windows 源码部署如需启用 Hashcat GUI，建议准备独立的 Hashcat 目录和字典目录
- 如需启用编码转换工具，建议准备本地 CyberChef 目录

### Docker 部署

- Docker
- Docker Compose Plugin
- Linux Docker 场景下，如需启用 Hashcat GUI，需要宿主机提供 Linux 版 Hashcat 目录和字典目录

## 配置文件加载规则

后端启动时会按以下顺序加载配置：

1. 项目根目录 `.env`
2. `backend/.env`，并覆盖同名项

这意味着：

- Docker 部署主要使用根目录 `.env`
- 源码部署可以复制根目录 `.env`，再用 `backend/.env` 覆盖本机路径

## 一、源码部署

源码部署更适合以下场景：

- Windows 本机运行 Hashcat
- 本地开发和联调
- 需要直接挂接本机 CyberChef/Hashcat 目录

### 1. 复制配置文件

在项目根目录执行：

```bash
cp .env.example .env
cp backend/.env.example backend/.env
```

Windows PowerShell：

```powershell
Copy-Item .env.example .env
Copy-Item backend/.env.example backend/.env
```

### 2. 修改关键配置

#### 根目录 `.env`

源码部署时建议至少检查这些项：

- `FRONTEND_PORT`
- `BACKEND_PORT`
- `AI_API_BASE_URL`
- `AI_API_KEY`
- `AI_MODEL`

#### `backend/.env`

源码部署时重点检查这些项：

- `APP_ENV=development`
- `CORS_ALLOW_ALL=true`
- `HASHCAT_BINARY_PATH`
- `HASHCAT_BUNDLE_DIR`
- `HASHCAT_WORDLISTS_DIR`
- `CYBERCHEF_DIR`
- `TOOL_HASHCAT_GUI_ENABLED=true`
- `TOOL_ENCODING_CONVERTER_ENABLED=true`

Windows 示例：

```env
HASHCAT_BINARY_PATH=
HASHCAT_BUNDLE_DIR=D:/Tools/hashcat-7.1.2
HASHCAT_WORDLISTS_DIR=D:/Tools/hashcat-wordlists
CYBERCHEF_DIR=D:/CyberChef/CyberChef_en
TOOL_HASHCAT_GUI_ENABLED=true
TOOL_ENCODING_CONVERTER_ENABLED=true
```

说明：

- 如果 `HASHCAT_BINARY_PATH` 留空，系统会继续尝试 `HASHCAT_BUNDLE_DIR`
- `HASHCAT_WORDLISTS_DIR` 建议单独存放 `rockyou.txt` 等字典
- `CYBERCHEF_DIR` 仅本地部署需要，服务器 Docker 通常保持关闭

### 3. 启动后端

#### Windows PowerShell

```powershell
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install --upgrade pip
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

#### Linux / macOS

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

后端默认访问地址：

- API：`http://127.0.0.1:8000/api/v1`
- 健康检查：`http://127.0.0.1:8000/health`

### 4. 启动前端

新开一个终端：

```bash
cd frontend
npm install
npm run dev
```

前端默认地址：

- `http://127.0.0.1:5173`

说明：

- `frontend/vite.config.ts` 已内置开发代理
- 默认会把 `/api` 和 `/storage` 代理到 `http://127.0.0.1:8000`
- 如果后端不在 `127.0.0.1:8000`，可临时指定：

```bash
VITE_DEV_PROXY_TARGET=http://127.0.0.1:9000 npm run dev
```

Windows PowerShell：

```powershell
$env:VITE_DEV_PROXY_TARGET="http://127.0.0.1:9000"
npm run dev
```

### 5. 源码部署访问方式

- 前端页面：`http://127.0.0.1:5173`
- 后端 API：`http://127.0.0.1:8000/api/v1`

## 二、Docker 部署

Docker 部署更适合以下场景：

- Linux 服务器
- 本地一键拉起前后端
- 需要通过宿主机挂载持久化目录

### 1. 复制主配置

```bash
cp .env.example .env
```

### 2. 修改根目录 `.env`

建议至少检查以下项：

- `FRONTEND_PORT`
- `BACKEND_PORT`
- `FRONTEND_VITE_API_BASE_URL`
- `AI_API_BASE_URL`
- `AI_API_KEY`
- `AI_MODEL`
- `TOOL_HASHCAT_GUI_ENABLED`
- `TOOL_ENCODING_CONVERTER_ENABLED`
- `BACKEND_HASHCAT_BUNDLE_DIR`
- `BACKEND_HASHCAT_WORDLISTS_DIR`
- `HASHCAT_BUNDLE_DIR`
- `HASHCAT_WORDLISTS_DIR`

默认建议：

```env
FRONTEND_PORT=8080
BACKEND_PORT=8000
FRONTEND_VITE_API_BASE_URL=/api/v1

BACKEND_HASHCAT_BUNDLE_DIR=./docker-data/backend/hashcat-bundle
BACKEND_HASHCAT_WORDLISTS_DIR=./docker-data/backend/hashcat-wordlists

HASHCAT_BUNDLE_DIR=/opt/hashcat
HASHCAT_WORDLISTS_DIR=/opt/hashcat-wordlists
HASHCAT_RUNTIME_DIR=storage/data/hashcat-runtime
```

说明：

- `BACKEND_HASHCAT_BUNDLE_DIR` 是宿主机目录
- `HASHCAT_BUNDLE_DIR=/opt/hashcat` 是容器内目录
- `docker-compose.yml` 已把宿主机目录挂载到容器

### 3. 准备宿主机挂载目录

Linux / macOS：

```bash
mkdir -p \
  docker-data/backend/data \
  docker-data/backend/uploads \
  docker-data/backend/logs \
  docker-data/backend/reports \
  docker-data/backend/hashcat-bundle \
  docker-data/backend/hashcat-wordlists
```

Windows PowerShell：

```powershell
New-Item -ItemType Directory -Force docker-data/backend/data | Out-Null
New-Item -ItemType Directory -Force docker-data/backend/uploads | Out-Null
New-Item -ItemType Directory -Force docker-data/backend/logs | Out-Null
New-Item -ItemType Directory -Force docker-data/backend/reports | Out-Null
New-Item -ItemType Directory -Force docker-data/backend/hashcat-bundle | Out-Null
New-Item -ItemType Directory -Force docker-data/backend/hashcat-wordlists | Out-Null
```

### 4. 准备 Hashcat 外部目录

如果你需要在 Docker 中启用 Hashcat GUI：

1. 把 Linux 版 Hashcat 可执行文件和资源目录放到：

   - `./docker-data/backend/hashcat-bundle`

2. 把字典文件放到：

   - `./docker-data/backend/hashcat-wordlists`

3. 至少保证字典目录下存在：

   - `rockyou.txt`

4. 把 `.env` 中以下项打开：

```env
TOOL_HASHCAT_GUI_ENABLED=true
```

如果你不打算在 Docker 环境启用 Hashcat，保持：

```env
TOOL_HASHCAT_GUI_ENABLED=false
```

### 5. 启动容器

```bash
docker compose up -d --build
```

查看状态：

```bash
docker compose ps
docker compose logs -f backend
docker compose logs -f frontend
```

### 6. 访问地址

- 前端：`http://127.0.0.1:${FRONTEND_PORT}`
- 后端健康检查：`http://127.0.0.1:${BACKEND_PORT}/health`

默认情况下：

- 前端暴露到公网或内网端口
- 后端仅绑定到本机 `127.0.0.1:${BACKEND_PORT}`

如果你使用 Nginx、Caddy、宝塔或 1Panel 做反向代理，通常只需要代理前端即可：

- `http://127.0.0.1:${FRONTEND_PORT}`

### 7. 停止和更新

停止：

```bash
docker compose down
```

保留数据重新构建：

```bash
docker compose up -d --build
```

只看后端日志：

```bash
docker compose logs -f backend
```
