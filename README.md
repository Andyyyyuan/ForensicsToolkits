# 部署方法

## Release 包含文件

- `docker-compose.yml`：本地构建前后端镜像并启动容器
- `.env.example`：部署环境变量模板

## 首次使用

```bash
cp .env.example .env
docker compose up -d
```

## 需要修改的配置

至少检查并修改以下项：

- `FRONTEND_PORT`：前端对外暴露端口
- `BACKEND_PORT`：仅绑定到本机 `127.0.0.1` 的后端调试端口
- `CORS_ALLOW_ORIGINS`：如果你会让域名或反向代理直连后端，需要改成实际来源
- `AI_API_BASE_URL`、`AI_API_KEY`、`AI_MODEL`：如果你需要 AI 分析功能，请配置ApiKey
- `TOOL_HASHCAT_GUI_ENABLED`：服务器部署建议保持 `false`
- `TOOL_ENCODING_CONVERTER_ENABLED`：默认保持 `false`

如果你打算用 Nginx、Caddy、宝塔或 1Panel做域名反代，通常反代到：

- http://127.0.0.1:${FRONTEND_PORT}

即可，不需要单独把后端暴露到公网。

## 目录说明

运行数据默认保存在当前目录下：

- `./data/backend/data`
- `./data/backend/uploads`
- `./data/backend/logs`
- `./data/backend/reports`

项目持续更新，欢迎大家在issue提需求和建议！