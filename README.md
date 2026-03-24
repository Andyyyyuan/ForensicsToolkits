# ForensicsToolkits

## 部署方式

本项目支持两种常用部署方式：

- 源码部署
- Docker 部署

## 源码部署

### 1. 环境配置

```bash
cp .env.example .env
cp backend/.env.example backend/.env
```

Windows PowerShell：

```powershell
Copy-Item .env.example .env
Copy-Item backend/.env.example backend/.env
```

### 2. 启动后端

Windows PowerShell：

```powershell
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install --upgrade pip
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Linux / macOS：

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### 3. 启动前端

```bash
cd frontend
npm install
npm run dev
```

默认访问地址：

- 前端：`http://127.0.0.1:5173`
- 后端：`http://127.0.0.1:8000/api/v1`

## Docker 部署

### 1. 准备配置

```bash
cp .env.example .env
```

### 2. 启动容器

```bash
docker compose up -d --build
```

默认访问地址为`http://127.0.0.1:8080`