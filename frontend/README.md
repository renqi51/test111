# Frontend

```bash
npm install
npm run dev
```

默认通过 Vite 将 `/api` 代理到 `http://127.0.0.1:8000`。若前后端分离部署，可设置环境变量：

```text
VITE_API_BASE=https://your-api-host
```

构建：

```bash
npm run build
```

产物在 `dist/`。
