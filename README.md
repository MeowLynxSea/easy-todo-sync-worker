# Easy Todo Sync Worker

可自部署的 Cloudflare Worker 同步/认证后端，使用 **Cloudflare D1** 持久化。

## 一键部署到 Cloudflare

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/MeowLynxSea/easy-todo-sync-worker)

对于零基础用户，请参考以下指导：

1. 点击上面的 **Deploy to Cloudflare** 按钮
2. 按向导提示创建并绑定 **D1 数据库**（一般直接下一步即可）
3. 部署完成后，进入 **设置-变量和机密** 添加以下变量，类型选择 **密钥**：
   - `JWT_SECRET`
   - `TOKEN_PEPPER`
   - `OAUTH_PROVIDERS_JSON`

其中，`OAUTH_PROVIDERS_JSON`变量的值的一个例子为：

```
[{"name":"github","authorizeUrl":"https://github.com/login/oauth/authorize","tokenUrl":"https://github.com/login/oauth/access_token","userinfoUrl":"https://api.github.com/user","clientId":"YOUR_CLIENT_ID","clientSecret":"YOUR_CLIENT_SECRET","scope":"","idField":"id","accessTokenField":"access_token","extraAuthorizeParams":{},"extraTokenParams":{}}]
```

在申请OAuth时，请将回调地址填写为：**您的项目部署地址（一般是https://easy-todo-sync-worker.您的Cloudflare用户名.workers.dev）** + /v1/auth/callback

如：`https://easy-todo-sync-worker.somebody.workers.dev/v1/auth/callback`

注：您需要使用自己的部署地址，上面这个地址是不存在的，只为了说明您填入的回调地址应该长什么样。

注：您可以配置多个 OAuth Privider，但是需要相应的修改各个参数。对于自用来说，我们推荐使用 Github。

## 自部署（Wrangler CLI）

前置：Node.js 18+，Cloudflare 账号（wrangler 会引导登录）。

1. 安装依赖（需要联网）：`npm i`
2. 准备配置：
   - 复制模板：`cp wrangler.toml.example wrangler.toml`
   - 修改 `name`（Worker 名称全局唯一）
3. 创建 D1 + 回填 ID + 应用迁移（远程）：`npm run d1:bootstrap`
5. 设置生产 secrets（强烈建议）：
   - `npx wrangler secret put JWT_SECRET`
   - `npx wrangler secret put TOKEN_PEPPER`
   - `npx wrangler secret put OAUTH_PROVIDERS_JSON`
6. 部署：`npm run deploy`

## 本地开发（wrangler dev）

1. 安装依赖（需要联网）：`npm i`
2. 配置环境变量：`cp .dev.vars.example .dev.vars` 并填写
3. 应用迁移（本地）：`npm run d1:migrate:local`
4. 启动：`npm run dev`

## 生产部署要点

- `BASE_URL` 建议设置为你对外使用的固定域名（用于 OAuth callback：`BASE_URL/v1/auth/callback`）
  - 不设置时，服务端会使用请求的 `origin` 作为 `BASE_URL`（适合直接用 `*.workers.dev`）
- `OAUTH_PROVIDERS_JSON` 含 client secret，请不要写进仓库，建议用 `wrangler secret put` 配置
- `JWT_SECRET` / `TOKEN_PEPPER` 生产必须更换

## 配置项

- `BASE_URL`：可选；默认取请求 `origin`（OAuth 回调必须与注册的回调域名一致，推荐固定一个域名）
- `CORS_ALLOW_ORIGINS`：可选；默认 `*`（开发方便）。生产建议填逗号分隔的 origin 列表，如 `https://app.example.com,http://localhost:8080`
- `CORS_ALLOW_CREDENTIALS`：可选；默认 `false`。只有在你需要跨域携带 cookies（`fetch(..., { credentials: "include" })`）时才开启；开启后不能用 `*`，需要配 `CORS_ALLOW_ORIGINS`
- `JWT_SECRET`：默认 `dev-secret-change-me`（生产必须改）
- `JWT_ISSUER`：默认 `easy_todo_sync_server`
- `TOKEN_PEPPER`：默认 `dev-pepper-change-me`（生产必须改）
- `APP_REDIRECT_ALLOWLIST`：默认 `easy_todo://`
- `AUTH_PROVIDERS`：可选；不填则启用全部已配置 provider
- `OAUTH_PROVIDERS_JSON`：OAuth provider 配置（建议作为 secret；示例见 `.dev.vars.example`）
- `ACCESS_TOKEN_TTL_SECS`：默认 900
- `REFRESH_TOKEN_TTL_SECS`：默认 2592000
- `LOGIN_ATTEMPT_TTL_SECS`：默认 600
- `TICKET_TTL_SECS`：默认 120
- `MAX_PUSH_RECORDS`：默认 500

## API

- `GET /v1/health`
- `GET /v1/auth/providers`
- `GET /v1/auth/start?provider=...&app_redirect=...&client=easy_todo`
- `GET /v1/auth/web/start?provider=...&return_to=/...`
- `GET /v1/auth/callback?code=...&state=...`
- `POST /v1/auth/exchange` `{ "ticket": "..." }`
- `POST /v1/auth/refresh` `{ "refreshToken": "..." }`
- `POST /v1/auth/logout` `{ "refreshToken": "..." }`
- `GET /v1/key-bundle`（`Authorization: Bearer <accessToken>`）
- `PUT /v1/key-bundle`（`Authorization: Bearer <accessToken>`）
- `POST /v1/sync/push`（`Authorization: Bearer <accessToken>`）
- `GET /v1/sync/pull?since=<serverSeq>&limit=<n>&excludeDeviceId=<deviceId>`（`Authorization: Bearer <accessToken>`）

## 附件同步（Attachment）

Cloudflare Workers 版本已对齐 Rust `sync_server` 的附件分段上传/提交语义：

- `todo_attachment`：附件元信息记录（`recordId = <attachmentId>`）
- `todo_attachment_chunk`：附件分块记录（`recordId = <attachmentId>:<chunkIndex>`）
- `todo_attachment_commit`：提交标记（`recordId = <attachmentId>`）

服务端会先把 `todo_attachment`/`todo_attachment_chunk` 写入 `staged_records`，在收到对应的 `todo_attachment_commit` 之后再一次性提交到 `records`，从而让其它设备只会通过 `/v1/sync/pull` 看到“已提交完成”的附件数据。
