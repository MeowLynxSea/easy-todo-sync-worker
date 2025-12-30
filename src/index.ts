type D1Database = any;
type ExecutionContext = { waitUntil(promise: Promise<unknown>): void };

type JsonObject = Record<string, unknown>;

type Env = {
  DB: D1Database;
  BASE_URL?: string;
  JWT_SECRET?: string;
  JWT_ISSUER?: string;
  TOKEN_PEPPER?: string;
  APP_REDIRECT_ALLOWLIST?: string;
  AUTH_PROVIDERS?: string;
  OAUTH_PROVIDERS_JSON?: string;
  CORS_ALLOW_ORIGINS?: string;
  CORS_ALLOW_CREDENTIALS?: string;
  ACCESS_TOKEN_TTL_SECS?: string;
  REFRESH_TOKEN_TTL_SECS?: string;
  LOGIN_ATTEMPT_TTL_SECS?: string;
  TICKET_TTL_SECS?: string;
  MAX_PUSH_RECORDS?: string;
};

const MAX_RECORD_B64_LEN = 512 * 1024;
const MAX_PULL_LIMIT = 500;
const BODY_LIMIT_BYTES = 5 * 1024 * 1024;
const DEFAULT_MAX_PUSH_RECORDS = 500;

// Cloudflare D1 has a low bound-parameter limit per SQL statement. Keep batch
// sizes small to avoid `D1_ERROR: too many SQL variables`.
const D1_MAX_SQL_VARS = 100;
const D1_IN_CLAUSE_MAX_IDS = Math.max(1, D1_MAX_SQL_VARS - 2); // user_id + type
const D1_RECORDS_UPSERT_ROWS = Math.max(1, Math.floor(D1_MAX_SQL_VARS / 14)); // records insert has 14 vars/row
const D1_STAGED_UPSERT_ROWS = Math.max(1, Math.floor(D1_MAX_SQL_VARS / 13)); // staged_records insert has 13 vars/row

const TYPE_TODO_ATTACHMENT = "todo_attachment";
const TYPE_TODO_ATTACHMENT_CHUNK = "todo_attachment_chunk";
const TYPE_TODO_ATTACHMENT_COMMIT = "todo_attachment_commit";

type OAuthProviderConfig = {
  name: string;
  authorizeUrl: string;
  tokenUrl: string;
  userinfoUrl: string;
  clientId: string;
  clientSecret: string;
  scope?: string;
  idField?: string;
  accessTokenField?: string;
  extraAuthorizeParams?: Record<string, string>;
  extraTokenParams?: Record<string, string>;
  tokenAuthMethod?: string;
};

type AuthConfig = {
  baseUrl: string;
  jwtSecret: string;
  jwtIssuer: string;
  tokenPepper: string;
  appRedirectAllowlist: string[];
  accessTokenTtlSecs: number;
  refreshTokenTtlSecs: number;
  loginAttemptTtlSecs: number;
  ticketTtlSecs: number;
  enabledProviders: string[];
  providers: Map<string, OAuthProviderConfig>;
};

type AppConfig = {
  auth: AuthConfig;
  maxPushRecords: number;
  cors: CorsConfig;
};

let cachedConfigKey: string | null = null;
let cachedConfig: AppConfig | null = null;

let cachedJwtSecret: string | null = null;
let cachedJwtKey: CryptoKey | null = null;

const utf8Encoder = new TextEncoder();
const utf8Decoder = new TextDecoder();

type CorsConfig = {
  allowOrigins: string[] | null; // null = allow any
  allowCredentials: boolean;
};

function nowMsUtc(): number {
  return Date.now();
}

function jsonError(status: number, msg: string): Response {
  return new Response(JSON.stringify({ error: msg }), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

function dbError(): Response {
  return jsonError(500, "db error");
}

async function d1Run(env: Env, sql: string, ...binds: unknown[]) {
  try {
    return await env.DB.prepare(sql).bind(...binds).run();
  } catch (e) {
    console.error("D1 run error", e);
    throw dbError();
  }
}

async function d1First(env: Env, sql: string, ...binds: unknown[]) {
  try {
    return await env.DB.prepare(sql).bind(...binds).first();
  } catch (e) {
    console.error("D1 first error", e);
    throw dbError();
  }
}

async function d1All(env: Env, sql: string, ...binds: unknown[]) {
  try {
    return await env.DB.prepare(sql).bind(...binds).all();
  } catch (e) {
    console.error("D1 all error", e);
    throw dbError();
  }
}

function jsonResponse(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

function textResponse(text: string, status = 200): Response {
  return new Response(text, {
    status,
    headers: { "content-type": "text/plain; charset=utf-8" },
  });
}

function redirectResponse(to: string): Response {
  return new Response(null, {
    status: 307,
    headers: { location: to },
  });
}

function unquoteEnvJson(raw: string): string {
  const trimmed = raw.trim();
  if (
    (trimmed.startsWith("'") && trimmed.endsWith("'")) ||
    (trimmed.startsWith('"') && trimmed.endsWith('"'))
  ) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

function parseI64(raw: string | undefined): number | null {
  if (raw === null || raw === undefined) return null;
  if (typeof raw === "number") {
    if (!Number.isFinite(raw)) return null;
    return Math.trunc(raw);
  }
  const s = String(raw).trim();
  if (!s) return null;
  const n = Number.parseInt(s, 10);
  if (!Number.isFinite(n)) return null;
  return n;
}

function splitCsv(raw: unknown): string[] {
  if (raw === null || raw === undefined) return [];
  return String(raw)
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

function getBaseUrl(request: Request, env: Env): string {
  const fromEnv = String(env.BASE_URL ?? "").trim();
  if (fromEnv) return fromEnv;
  return new URL(request.url).origin;
}

function loadProvidersFromEnv(env: Env): Map<string, OAuthProviderConfig> {
  const raw = String(env.OAUTH_PROVIDERS_JSON ?? "[]");
  const json = unquoteEnvJson(raw);
  const list = JSON.parse(json) as OAuthProviderConfig[];
  const map = new Map<string, OAuthProviderConfig>();
  for (const p of Array.isArray(list) ? list : []) {
    const name = (p?.name ?? "").trim().toLowerCase();
    if (!name) continue;
    map.set(name, { ...p, name });
  }
  return map;
}

function loadConfig(request: Request, env: Env): AppConfig {
  const baseUrl = getBaseUrl(request, env);
  const key = [
    baseUrl,
    String(env.JWT_SECRET ?? ""),
    String(env.JWT_ISSUER ?? ""),
    String(env.TOKEN_PEPPER ?? ""),
    String(env.APP_REDIRECT_ALLOWLIST ?? ""),
    String(env.AUTH_PROVIDERS ?? ""),
    String(env.OAUTH_PROVIDERS_JSON ?? ""),
    String(env.CORS_ALLOW_ORIGINS ?? ""),
    String(env.CORS_ALLOW_CREDENTIALS ?? ""),
    String(env.ACCESS_TOKEN_TTL_SECS ?? ""),
    String(env.REFRESH_TOKEN_TTL_SECS ?? ""),
    String(env.LOGIN_ATTEMPT_TTL_SECS ?? ""),
    String(env.TICKET_TTL_SECS ?? ""),
    String(env.MAX_PUSH_RECORDS ?? ""),
  ].join("\n");

  if (cachedConfig && cachedConfigKey === key) return cachedConfig;

  const jwtSecret =
    String(env.JWT_SECRET ?? "dev-secret-change-me").trim() || "dev-secret-change-me";
  const jwtIssuer =
    String(env.JWT_ISSUER ?? "easy_todo_sync_server").trim() || "easy_todo_sync_server";
  const tokenPepper =
    String(env.TOKEN_PEPPER ?? "dev-pepper-change-me").trim() || "dev-pepper-change-me";

  const appRedirectAllowlist = splitCsv(env.APP_REDIRECT_ALLOWLIST ?? "easy_todo://");
  const providers = loadProvidersFromEnv(env);

  const enabledProviders = (() => {
    const allow = splitCsv(env.AUTH_PROVIDERS).map((s) => s.toLowerCase());
    if (allow.length > 0) return allow;
    return Array.from(providers.keys()).sort();
  })();

  const accessTokenTtlSecs = parseI64(env.ACCESS_TOKEN_TTL_SECS) ?? 15 * 60;
  const refreshTokenTtlSecs = parseI64(env.REFRESH_TOKEN_TTL_SECS) ?? 30 * 24 * 60 * 60;
  const loginAttemptTtlSecs = parseI64(env.LOGIN_ATTEMPT_TTL_SECS) ?? 10 * 60;
  const ticketTtlSecs = parseI64(env.TICKET_TTL_SECS) ?? 120;

  const maxPushRecords = parseI64(env.MAX_PUSH_RECORDS) ?? DEFAULT_MAX_PUSH_RECORDS;

  const corsAllowOriginsRaw = String(env.CORS_ALLOW_ORIGINS ?? "*").trim();
  const corsAllowOrigins = (() => {
    if (!corsAllowOriginsRaw || corsAllowOriginsRaw === "*") return null;
    const out: string[] = [];
    for (const raw of splitCsv(corsAllowOriginsRaw)) {
      try {
        out.push(new URL(raw).origin);
      } catch {
        // ignore invalid entries
      }
    }
    out.sort();
    return out.length > 0 ? out : null;
  })();
  const corsAllowCredentials = (() => {
    const raw = String(env.CORS_ALLOW_CREDENTIALS ?? "").trim().toLowerCase();
    return raw === "1" || raw === "true" || raw === "yes";
  })();

  const auth: AuthConfig = {
    baseUrl,
    jwtSecret,
    jwtIssuer,
    tokenPepper,
    appRedirectAllowlist,
    accessTokenTtlSecs: Math.max(1, accessTokenTtlSecs),
    refreshTokenTtlSecs: Math.max(60, refreshTokenTtlSecs),
    loginAttemptTtlSecs: Math.max(1, loginAttemptTtlSecs),
    ticketTtlSecs: Math.max(1, ticketTtlSecs),
    enabledProviders,
    providers,
  };

  cachedConfigKey = key;
  cachedConfig = {
    auth,
    maxPushRecords: Math.max(1, maxPushRecords),
    cors: { allowOrigins: corsAllowOrigins, allowCredentials: corsAllowCredentials },
  };
  return cachedConfig;
}

function getRemoteIp(request: Request): string | null {
  return (request.headers.get("CF-Connecting-IP") ?? "").trim() || null;
}

function shouldApplyCors(path: string): boolean {
  return path.startsWith("/v1/") || path.startsWith("/web/api/");
}

function buildCorsHeaders(request: Request, cors: CorsConfig): Headers | null {
  const origin = (request.headers.get("origin") ?? "").trim();
  const requestHeaders = (request.headers.get("access-control-request-headers") ?? "").trim();

  let allowOrigin: string | null = null;
  if (cors.allowCredentials) {
    if (origin) {
      if (!cors.allowOrigins || cors.allowOrigins.includes(origin)) allowOrigin = origin;
    }
  } else {
    if (!cors.allowOrigins) allowOrigin = "*";
    else if (origin && cors.allowOrigins.includes(origin)) allowOrigin = origin;
  }

  if (!allowOrigin) return null;

  const headers = new Headers();
  headers.set("access-control-allow-origin", allowOrigin);
  headers.set("access-control-allow-methods", "GET,POST,PUT,OPTIONS");
  headers.set(
    "access-control-allow-headers",
    requestHeaders || "authorization,content-type",
  );
  headers.set("access-control-max-age", "86400");

  if (cors.allowCredentials) headers.set("access-control-allow-credentials", "true");
  if (allowOrigin !== "*") headers.append("vary", "Origin");
  return headers;
}

function withCors(request: Request, cors: CorsConfig, response: Response): Response {
  const corsHeaders = buildCorsHeaders(request, cors);
  if (!corsHeaders) return response;

  const headers = new Headers(response.headers);
  for (const [k, v] of corsHeaders.entries()) headers.set(k, v);
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

function htmlEscape(s: string): string {
  return s
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function htmlResultPage(title: string, message: string, maybeRedirect: string | null): Response {
  const titleEsc = htmlEscape(title);
  const messageEsc = htmlEscape(message);
  const redirectEsc = maybeRedirect ? htmlEscape(maybeRedirect) : "";
  const redirectJson = maybeRedirect ? JSON.stringify(maybeRedirect) : "null";

  const body = `<!doctype html><html><head><meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>${titleEsc}</title>
<style>body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial;max-width:720px;margin:40px auto;padding:0 16px}a,button{font-size:16px}code{background:#f4f4f4;padding:2px 6px;border-radius:6px}</style>
</head><body><h1>${titleEsc}</h1><p>${messageEsc}</p>${
    maybeRedirect
      ? `<p><a href="${redirectEsc}">Return to app</a></p><script>window.location.href=${redirectJson};</script>`
      : ""
  }</body></html>`;

  return new Response(body, {
    status: 200,
    headers: { "content-type": "text/html; charset=utf-8" },
  });
}

function isAllowedWebReturnTo(returnTo: string): boolean {
  const s = returnTo.trim();
  if (!s.startsWith("/")) return false;
  if (s.startsWith("//")) return false;
  if (s.includes("://") || s.includes("\\")) return false;
  return true;
}

function isAllowedAppRedirect(cfg: AuthConfig, appRedirect: string): boolean {
  let appUrl: URL;
  try {
    appUrl = new URL(appRedirect.trim());
  } catch {
    return false;
  }

  const appScheme = appUrl.protocol.replace(":", "").toLowerCase();
  const appHost = (appUrl.hostname ?? "").toLowerCase();
  const appPort = (() => {
    if (appUrl.port) {
      const p = Number.parseInt(appUrl.port, 10);
      return Number.isFinite(p) ? p : null;
    }
    if (appScheme === "http") return 80;
    if (appScheme === "https") return 443;
    return null;
  })();
  const appPath = appUrl.pathname ?? "";
  const appFragment = (appUrl.hash ?? "").replace(/^#/, "");

  for (const raw0 of cfg.appRedirectAllowlist) {
    const raw = raw0.trim();
    if (!raw) continue;

    if (raw.endsWith("://")) {
      const scheme = raw.slice(0, -3).toLowerCase();
      if (scheme === appScheme && scheme !== "http" && scheme !== "https") return true;
      continue;
    }

    let allowed: URL;
    try {
      allowed = new URL(raw);
    } catch {
      continue;
    }

    const allowedScheme = allowed.protocol.replace(":", "").toLowerCase();
    if (allowedScheme !== appScheme) continue;

    const allowedHost = (allowed.hostname ?? "").toLowerCase();
    if (allowedHost !== appHost) continue;

    if (allowed.port) {
      const allowedPort = Number.parseInt(allowed.port, 10);
      if (Number.isFinite(allowedPort) && appPort !== allowedPort) continue;
    }

    const allowedPath = allowed.pathname ?? "";
    if (allowedPath !== "/" && allowedPath !== "") {
      if (allowedPath.endsWith("/")) {
        if (!appPath.startsWith(allowedPath)) continue;
      } else {
        if (!(appPath === allowedPath || appPath.startsWith(`${allowedPath}/`))) continue;
      }
    }

    const allowedFragment = (allowed.hash ?? "").replace(/^#/, "");
    if (allowedFragment && !appFragment.startsWith(allowedFragment)) continue;

    return true;
  }

  return false;
}

function appendTicket(appRedirect: string, ticket: string): string {
  const ticketEnc = encodeURIComponent(ticket);
  const [base, frag] = appRedirect.split("#", 2);

  let sep = "?";
  if (base.endsWith("?") || base.endsWith("&")) sep = "";
  else if (base.includes("?")) sep = "&";

  let out = `${base}${sep}ticket=${ticketEnc}`;
  if (frag !== undefined) out += `#${frag}`;
  return out;
}

function bytesToBase64Url(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!);
  const b64 = btoa(bin);
  return b64.replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function base64UrlToBytes(b64url: string): Uint8Array {
  const b64 = b64url.replaceAll("-", "+").replaceAll("_", "/");
  const padLen = (4 - (b64.length % 4)) % 4;
  const padded = b64 + "=".repeat(padLen);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function randomTokenB64(bytesLen: number): string {
  const bytes = new Uint8Array(bytesLen);
  crypto.getRandomValues(bytes);
  return bytesToBase64Url(bytes);
}

function hexEncode(bytes: ArrayBuffer): string {
  const u8 = new Uint8Array(bytes);
  let out = "";
  for (let i = 0; i < u8.length; i++) out += u8[i]!.toString(16).padStart(2, "0");
  return out;
}

async function sha256Hex(text: string): Promise<string> {
  const data = utf8Encoder.encode(text);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return hexEncode(digest);
}

async function hashToken(cfg: AuthConfig, token: string): Promise<string> {
  return sha256Hex(`${cfg.tokenPepper}:${token}`);
}

async function getJwtKey(secret: string): Promise<CryptoKey> {
  if (cachedJwtKey && cachedJwtSecret === secret) return cachedJwtKey;
  const key = await crypto.subtle.importKey(
    "raw",
    utf8Encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
  cachedJwtSecret = secret;
  cachedJwtKey = key;
  return key;
}

async function signJwtHs256(cfg: AuthConfig, claims: JsonObject): Promise<{ token: string; expiresIn: number }> {
  const nowMs = nowMsUtc();
  const nowSec = Math.max(0, Math.floor(nowMs / 1000));
  const expSec = nowSec + Math.max(1, Math.floor(cfg.accessTokenTtlSecs));

  const payload = { ...claims, iss: cfg.jwtIssuer, iat: nowSec, exp: expSec };
  const header = { alg: "HS256", typ: "JWT" };

  const encHeader = bytesToBase64Url(utf8Encoder.encode(JSON.stringify(header)));
  const encPayload = bytesToBase64Url(utf8Encoder.encode(JSON.stringify(payload)));
  const signingInput = `${encHeader}.${encPayload}`;

  const sigBuf = await crypto.subtle.sign("HMAC", await getJwtKey(cfg.jwtSecret), utf8Encoder.encode(signingInput));
  const sig = bytesToBase64Url(new Uint8Array(sigBuf));
  return { token: `${signingInput}.${sig}`, expiresIn: Math.max(1, Math.floor(cfg.accessTokenTtlSecs)) };
}

async function verifyJwtHs256(cfg: AuthConfig, jwt: string): Promise<JsonObject | null> {
  const parts = jwt.split(".");
  if (parts.length !== 3) return null;
  const [h, p, s] = parts;
  if (!h || !p || !s) return null;

  let sigBytes: Uint8Array;
  try {
    sigBytes = base64UrlToBytes(s);
  } catch {
    return null;
  }

  const ok = await crypto.subtle.verify("HMAC", await getJwtKey(cfg.jwtSecret), sigBytes, utf8Encoder.encode(`${h}.${p}`));
  if (!ok) return null;

  let payload: JsonObject;
  try {
    payload = JSON.parse(utf8Decoder.decode(base64UrlToBytes(p))) as JsonObject;
  } catch {
    return null;
  }

  if ((payload.iss ?? "") !== cfg.jwtIssuer) return null;
  const nowSec = Math.max(0, Math.floor(nowMsUtc() / 1000));
  const exp = typeof payload.exp === "number" ? payload.exp : Number.parseInt(String(payload.exp ?? ""), 10);
  if (!Number.isFinite(exp) || exp <= nowSec) return null;
  return payload;
}

function extractBearer(headers: Headers): string | null {
  const raw = (headers.get("authorization") ?? "").trim();
  const prefix = "bearer ";
  if (raw.length < prefix.length) return null;
  if (raw.slice(0, prefix.length).toLowerCase() !== prefix) return null;
  const token = raw.slice(prefix.length).trim();
  return token || null;
}

async function authenticateApiRequest(env: Env, cfg: AuthConfig, request: Request): Promise<{ userId: number }> {
  const jwt = extractBearer(request.headers);
  if (!jwt) throw jsonError(401, "missing bearer token");

  const payload = await verifyJwtHs256(cfg, jwt);
  if (!payload) throw jsonError(401, "invalid access token");

  const subRaw = payload.sub;
  const sidRaw = payload.sid;
  const userId = Number.parseInt(String(subRaw ?? ""), 10);
  const sessionId = Number.parseInt(String(sidRaw ?? ""), 10);
  if (!Number.isFinite(userId) || userId <= 0 || !Number.isFinite(sessionId) || sessionId <= 0) {
    throw jsonError(401, "invalid access token");
  }

  const row = await d1First(
    env,
    `SELECT user_id, expires_at_ms_utc, revoked_at_ms_utc FROM refresh_tokens WHERE id = ?`,
    sessionId,
  );

  if (!row) throw jsonError(401, "invalid access token");

  const sidUserId = Number.parseInt(String((row as any).user_id ?? ""), 10);
  const expiresAtMs = Number.parseInt(String((row as any).expires_at_ms_utc ?? ""), 10);
  const revokedAtMs = (row as any).revoked_at_ms_utc as number | null;

  const nowMs = nowMsUtc();
  if (!Number.isFinite(sidUserId) || sidUserId !== userId) throw jsonError(401, "invalid access token");
  if (revokedAtMs !== null && revokedAtMs !== undefined) throw jsonError(401, "invalid access token");
  if (!Number.isFinite(expiresAtMs) || expiresAtMs <= nowMs) throw jsonError(401, "invalid access token");

  return { userId };
}

async function readJsonBody(request: Request, maxBytes: number): Promise<unknown> {
  const contentLen = request.headers.get("content-length");
  if (contentLen) {
    const n = Number.parseInt(contentLen, 10);
    if (Number.isFinite(n) && n > maxBytes) throw jsonError(413, "payload too large");
  }

  const buf = await request.arrayBuffer();
  if (buf.byteLength > maxBytes) throw jsonError(413, "payload too large");
  try {
    return JSON.parse(utf8Decoder.decode(buf));
  } catch {
    throw jsonError(400, "invalid json");
  }
}

async function ensureUser(env: Env, provider: string, sub: string, nowMs: number): Promise<{ userId: number; created: boolean }> {
  const insert = await d1Run(
    env,
    `INSERT INTO users (oauth_provider, oauth_sub, created_at_ms_utc)
     VALUES (?, ?, ?)
     ON CONFLICT(oauth_provider, oauth_sub) DO NOTHING`,
    provider,
    sub,
    nowMs,
  );
  const created = (insert?.meta?.changes ?? 0) > 0;

  const row = await d1First(
    env,
    `SELECT id FROM users WHERE oauth_provider = ? AND oauth_sub = ?`,
    provider,
    sub,
  );
  const userId = Number.parseInt(String((row as any)?.id ?? ""), 10);
  if (!Number.isFinite(userId) || userId <= 0) throw dbError();
  return { userId, created };
}

async function issueTokensForUser(env: Env, cfg: AuthConfig, userId: number, rotatedFromId: number | null, nowMs: number) {
  const refreshExpiresAtMs = nowMs + Math.floor(cfg.refreshTokenTtlSecs * 1000);

  for (let attempt = 0; attempt < 3; attempt++) {
    const refreshToken = randomTokenB64(32);
    const tokenHash = await hashToken(cfg, refreshToken);
    const res = await d1Run(
      env,
      `INSERT INTO refresh_tokens (user_id, token_hash, created_at_ms_utc, expires_at_ms_utc, rotated_from_id)
       VALUES (?, ?, ?, ?, ?)`,
      userId,
      tokenHash,
      nowMs,
      refreshExpiresAtMs,
      rotatedFromId,
    );

    if ((res?.meta?.changes ?? 0) === 1) {
      const sessionId = Number.parseInt(String(res?.meta?.last_row_id ?? ""), 10);
      if (!Number.isFinite(sessionId) || sessionId <= 0) throw dbError();
      const { token: accessToken, expiresIn } = await signJwtHs256(cfg, { sub: String(userId), sid: sessionId });
      return { accessToken, expiresIn, refreshToken };
    }
  }

  throw dbError();
}

function providerIsEnabled(cfg: AuthConfig, provider: string): boolean {
  const p = provider.toLowerCase();
  if (!cfg.providers.has(p)) return false;
  return cfg.enabledProviders.includes(p);
}

async function oauthAuthorizeUrl(cfg: AuthConfig, provider: string, state: string): Promise<string> {
  const p = provider.toLowerCase();
  const pCfg = cfg.providers.get(p);
  if (!pCfg) throw new Error("provider not configured");

  const redirectUri = `${cfg.baseUrl.replace(/\/+$/, "")}/v1/auth/callback`;

  const url = new URL(pCfg.authorizeUrl);
  url.searchParams.set("client_id", pCfg.clientId);
  url.searchParams.set("redirect_uri", redirectUri);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("state", state);
  if (pCfg.scope && pCfg.scope.trim()) url.searchParams.set("scope", pCfg.scope);
  if (pCfg.extraAuthorizeParams) {
    for (const [k, v] of Object.entries(pCfg.extraAuthorizeParams)) url.searchParams.set(k, v);
  }
  return url.toString();
}

async function oauthExchangeCode(cfg: AuthConfig, provider: string, code: string): Promise<string> {
  const p = provider.toLowerCase();
  const pCfg = cfg.providers.get(p);
  if (!pCfg) throw new Error("provider not configured");

  const redirectUri = `${cfg.baseUrl.replace(/\/+$/, "")}/v1/auth/callback`;

  const params = new URLSearchParams();
  params.set("code", code);
  params.set("redirect_uri", redirectUri);
  params.set("grant_type", "authorization_code");
  if (pCfg.extraTokenParams) {
    for (const [k, v] of Object.entries(pCfg.extraTokenParams)) params.set(k, v);
  }

  const tokenAuthMethod = (pCfg.tokenAuthMethod ?? "basic").toLowerCase();
  const headers: Record<string, string> = { accept: "application/json" };

  if (tokenAuthMethod === "basic") {
    headers.authorization = `Basic ${btoa(`${pCfg.clientId}:${pCfg.clientSecret}`)}`;
  } else if (tokenAuthMethod === "post") {
    params.set("client_id", pCfg.clientId);
    params.set("client_secret", pCfg.clientSecret);
  } else {
    throw new Error(`unsupported tokenAuthMethod: ${tokenAuthMethod}`);
  }

  const resp = await fetch(pCfg.tokenUrl, {
    method: "POST",
    headers: { ...headers, "content-type": "application/x-www-form-urlencoded" },
    body: params.toString(),
  });
  const text = await resp.text();
  if (!resp.ok) throw new Error(`token response status: ${resp.status}`);

  const accessTokenField = pCfg.accessTokenField ?? "access_token";

  try {
    const val = JSON.parse(text) as any;
    const tok = val?.[accessTokenField];
    if (typeof tok === "string" && tok.trim()) return tok.trim();
  } catch {
    // ignore
  }

  const parsed = new URLSearchParams(text);
  const tok2 = parsed.get(accessTokenField);
  if (tok2 && tok2.trim()) return tok2.trim();

  throw new Error("missing access_token in token response");
}

function extractJsonStringField(val: any, dotPath: string): string | null {
  const parts = dotPath.split(".").map((s) => s.trim()).filter(Boolean);
  let cur: any = val;
  for (const part of parts) {
    if (!cur || typeof cur !== "object") return null;
    cur = cur[part];
  }
  if (cur === null || cur === undefined) return null;
  if (typeof cur === "string") return cur;
  if (typeof cur === "number" || typeof cur === "boolean") return String(cur);
  return null;
}

async function oauthFetchSubject(cfg: AuthConfig, provider: string, accessToken: string): Promise<string> {
  const p = provider.toLowerCase();
  const pCfg = cfg.providers.get(p);
  if (!pCfg) throw new Error("provider not configured");

  const resp = await fetch(pCfg.userinfoUrl, {
    method: "GET",
    headers: {
      accept: "application/json",
      "user-agent": "easy_todo_sync_worker",
      authorization: `Bearer ${accessToken}`,
    },
  });
  if (!resp.ok) throw new Error(`userinfo response status: ${resp.status}`);
  const val = (await resp.json()) as any;

  const idField = (pCfg.idField ?? "id").trim() || "id";
  const sub = extractJsonStringField(val, idField);
  if (!sub || !sub.trim()) throw new Error(`missing user id field: ${idField}`);
  return sub.trim();
}

function cookieSecureFlag(baseUrl: string): boolean {
  return baseUrl.trimStart().toLowerCase().startsWith("https://");
}

function buildSetCookie(name: string, value: string, maxAgeSecs: number, secure: boolean): string {
  let s = `${name}=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAgeSecs}`;
  if (secure) s += "; Secure";
  return s;
}

async function authProviders(request: Request, env: Env): Promise<Response> {
  const cfg = loadConfig(request, env).auth;
  const providers = cfg.enabledProviders.filter((p) => cfg.providers.has(p)).sort();
  return jsonResponse({ providers: providers.map((name) => ({ name })) });
}

async function authStart(request: Request, env: Env): Promise<Response> {
  const appCfg = loadConfig(request, env);
  const cfg = appCfg.auth;
  const url = new URL(request.url);
  const provider = (url.searchParams.get("provider") ?? "").trim().toLowerCase();
  const appRedirect = (url.searchParams.get("app_redirect") ?? "").trim();
  const client = (url.searchParams.get("client") ?? "easy_todo").trim() || "easy_todo";

  if (!cfg.providers.has(provider)) return jsonError(400, "provider not configured");
  if (!providerIsEnabled(cfg, provider)) return jsonError(400, "provider not enabled");
  if (!isAllowedAppRedirect(cfg, appRedirect)) return jsonError(400, "app_redirect not allowed");

  const stateToken = randomTokenB64(24);
  const nowMs = nowMsUtc();
  const expiresAtMs = nowMs + Math.floor(cfg.loginAttemptTtlSecs * 1000);

  await d1Run(
    env,
    `INSERT INTO auth_login_attempts
       (state, provider, app_redirect, client, created_at_ms_utc, expires_at_ms_utc)
     VALUES (?, ?, ?, ?, ?, ?)`,
    stateToken,
    provider,
    appRedirect,
    client,
    nowMs,
    expiresAtMs,
  );

  let authUrl: string;
  try {
    authUrl = await oauthAuthorizeUrl(cfg, provider, stateToken);
  } catch {
    return jsonError(500, "oauth config error");
  }
  return redirectResponse(authUrl);
}

async function authWebStart(request: Request, env: Env): Promise<Response> {
  const appCfg = loadConfig(request, env);
  const cfg = appCfg.auth;
  const url = new URL(request.url);
  const provider = (url.searchParams.get("provider") ?? "").trim().toLowerCase();
  const returnTo = (url.searchParams.get("return_to") ?? "").trim();

  if (!cfg.providers.has(provider)) return jsonError(400, "provider not configured");
  if (!providerIsEnabled(cfg, provider)) return jsonError(400, "provider not enabled");
  if (!isAllowedWebReturnTo(returnTo)) return jsonError(400, "return_to not allowed");

  const stateToken = randomTokenB64(24);
  const nowMs = nowMsUtc();
  const expiresAtMs = nowMs + Math.floor(cfg.loginAttemptTtlSecs * 1000);

  await d1Run(
    env,
    `INSERT INTO auth_login_attempts
       (state, provider, app_redirect, client, created_at_ms_utc, expires_at_ms_utc)
     VALUES (?, ?, ?, ?, ?, ?)`,
    stateToken,
    provider,
    returnTo,
    "web",
    nowMs,
    expiresAtMs,
  );

  let authUrl: string;
  try {
    authUrl = await oauthAuthorizeUrl(cfg, provider, stateToken);
  } catch {
    return jsonError(500, "oauth config error");
  }
  return redirectResponse(authUrl);
}

async function authCallback(request: Request, env: Env): Promise<Response> {
  const appCfg = loadConfig(request, env);
  const cfg = appCfg.auth;
  const url = new URL(request.url);

  const state = (url.searchParams.get("state") ?? "").trim();
  const code = (url.searchParams.get("code") ?? "").trim() || null;
  const err = (url.searchParams.get("error") ?? "").trim() || null;
  const errDesc = (url.searchParams.get("error_description") ?? "").trim() || "OAuth error";

  if (err) return htmlResultPage("Login failed", `${err}: ${errDesc}`, null);
  if (!code) return htmlResultPage("Login failed", "missing code", null);

  const row = await d1First(
    env,
    `SELECT provider, app_redirect, client, expires_at_ms_utc
       FROM auth_login_attempts WHERE state = ?`,
    state,
  );

  if (!row) return htmlResultPage("Login failed", "invalid or expired state", null);

  const provider = String((row as any).provider ?? "").trim().toLowerCase();
  const appRedirect = String((row as any).app_redirect ?? "");
  const client = String((row as any).client ?? "");
  const expiresAtMs = Number.parseInt(String((row as any).expires_at_ms_utc ?? ""), 10);

  const nowMs = nowMsUtc();
  if (!Number.isFinite(expiresAtMs) || expiresAtMs <= nowMs) {
    await d1Run(env, `DELETE FROM auth_login_attempts WHERE state = ?`, state);
    return htmlResultPage("Login failed", "state expired", null);
  }

  // One-time state.
  await d1Run(env, `DELETE FROM auth_login_attempts WHERE state = ?`, state);

  let providerAccessToken: string;
  try {
    providerAccessToken = await oauthExchangeCode(cfg, provider, code);
  } catch {
    return htmlResultPage("Login failed", "OAuth code exchange failed", null);
  }

  let sub: string;
  try {
    sub = await oauthFetchSubject(cfg, provider, providerAccessToken);
  } catch {
    return htmlResultPage("Login failed", "OAuth userinfo failed", null);
  }

  let userId: number;
  try {
    userId = (await ensureUser(env, provider, sub, nowMs)).userId;
  } catch {
    return htmlResultPage("Login failed", "db error", null);
  }

  if (client === "web") {
    let tokens: { accessToken: string; expiresIn: number; refreshToken: string };
    try {
      tokens = await issueTokensForUser(env, cfg, userId, null, nowMs);
    } catch {
      return htmlResultPage("Login failed", "db error", null);
    }

    let returnTo = appRedirect;
    if (!isAllowedWebReturnTo(returnTo)) returnTo = "/dashboard";
    const base = cfg.baseUrl.replace(/\/+$/, "");
    const redirectTo = `${base}${returnTo}`;

    const secure = cookieSecureFlag(cfg.baseUrl);
    const refreshMaxAge = Math.max(0, Math.floor(cfg.refreshTokenTtlSecs));

    const headers = new Headers();
    headers.append("set-cookie", buildSetCookie("easy_todo_access", tokens.accessToken, tokens.expiresIn, secure));
    headers.append("set-cookie", buildSetCookie("easy_todo_refresh", tokens.refreshToken, refreshMaxAge, secure));
    headers.set("location", redirectTo);
    return new Response(null, { status: 307, headers });
  }

  const ticket = randomTokenB64(32);
  const ticketHash = await hashToken(cfg, ticket);
  const ticketExpiresAtMs = nowMs + Math.floor(cfg.ticketTtlSecs * 1000);

  await d1Run(
    env,
    `INSERT INTO auth_tickets
       (ticket_hash, user_id, created_at_ms_utc, expires_at_ms_utc, consumed_at_ms_utc)
     VALUES (?, ?, ?, ?, NULL)`,
    ticketHash,
    userId,
    nowMs,
    ticketExpiresAtMs,
  );

  const returnUrl = appendTicket(appRedirect, ticket);
  return htmlResultPage("Login succeeded", "You can return to the app now.", returnUrl);
}

async function authExchange(request: Request, env: Env): Promise<Response> {
  const cfg = loadConfig(request, env).auth;
  const body = (await readJsonBody(request, BODY_LIMIT_BYTES)) as any;
  const ticket = String(body?.ticket ?? "").trim();
  if (!ticket) return jsonError(400, "ticket required");

  const nowMs = nowMsUtc();
  const ticketHash = await hashToken(cfg, ticket);

  const row = await d1First(
    env,
    `SELECT user_id, expires_at_ms_utc, consumed_at_ms_utc
       FROM auth_tickets WHERE ticket_hash = ?`,
    ticketHash,
  );

  if (!row) return jsonError(401, "invalid ticket");

  const userId = Number.parseInt(String((row as any).user_id ?? ""), 10);
  const expiresAtMs = Number.parseInt(String((row as any).expires_at_ms_utc ?? ""), 10);
  const consumedAtMs = (row as any).consumed_at_ms_utc as number | null;

  if (consumedAtMs !== null && consumedAtMs !== undefined) return jsonError(401, "ticket expired");
  if (!Number.isFinite(expiresAtMs) || expiresAtMs <= nowMs) return jsonError(401, "ticket expired");

  const updated = await d1Run(
    env,
    `UPDATE auth_tickets
       SET consumed_at_ms_utc = ?
     WHERE ticket_hash = ? AND consumed_at_ms_utc IS NULL`,
    nowMs,
    ticketHash,
  );
  if ((updated?.meta?.changes ?? 0) !== 1) return jsonError(401, "ticket already consumed");

  let tokens: { accessToken: string; expiresIn: number; refreshToken: string };
  try {
    tokens = await issueTokensForUser(env, cfg, userId, null, nowMs);
  } catch {
    return jsonError(500, "db error");
  }

  return jsonResponse({
    accessToken: tokens.accessToken,
    expiresIn: tokens.expiresIn,
    refreshToken: tokens.refreshToken,
  });
}

async function authRefresh(request: Request, env: Env): Promise<Response> {
  const cfg = loadConfig(request, env).auth;
  const body = (await readJsonBody(request, BODY_LIMIT_BYTES)) as any;
  const refreshToken = String(body?.refreshToken ?? "").trim();
  if (!refreshToken) return jsonError(400, "refreshToken required");

  const nowMs = nowMsUtc();
  const tokenHash = await hashToken(cfg, refreshToken);

  const row = await d1First(
    env,
    `UPDATE refresh_tokens
       SET revoked_at_ms_utc = ?, last_used_at_ms_utc = ?
     WHERE token_hash = ?
       AND revoked_at_ms_utc IS NULL
       AND expires_at_ms_utc > ?
     RETURNING id, user_id`,
    nowMs,
    nowMs,
    tokenHash,
    nowMs,
  );

  if (!row) return jsonError(401, "refresh token expired");

  const oldId = Number.parseInt(String((row as any).id ?? ""), 10);
  const userId = Number.parseInt(String((row as any).user_id ?? ""), 10);
  if (!Number.isFinite(oldId) || oldId <= 0 || !Number.isFinite(userId) || userId <= 0) {
    return jsonError(401, "refresh token expired");
  }

  let tokens: { accessToken: string; expiresIn: number; refreshToken: string };
  try {
    tokens = await issueTokensForUser(env, cfg, userId, oldId, nowMs);
  } catch {
    return jsonError(500, "db error");
  }

  return jsonResponse({
    accessToken: tokens.accessToken,
    expiresIn: tokens.expiresIn,
    refreshToken: tokens.refreshToken,
  });
}

async function authLogout(request: Request, env: Env): Promise<Response> {
  const cfg = loadConfig(request, env).auth;
  const body = (await readJsonBody(request, BODY_LIMIT_BYTES)) as any;
  const refreshToken = String(body?.refreshToken ?? "").trim();
  if (!refreshToken) return jsonError(400, "refreshToken required");

  const nowMs = nowMsUtc();
  const tokenHash = await hashToken(cfg, refreshToken);
  await d1Run(
    env,
    `UPDATE refresh_tokens
       SET revoked_at_ms_utc = ?
     WHERE token_hash = ? AND revoked_at_ms_utc IS NULL`,
    nowMs,
    tokenHash,
  );

  return jsonResponse({ ok: true });
}

async function getKeyBundle(request: Request, env: Env): Promise<Response> {
  const { auth } = loadConfig(request, env);
  const user = await authenticateApiRequest(env, auth, request);

  const row = await d1First(
    env,
    `SELECT bundle_version, bundle_json FROM key_bundles WHERE user_id = ?`,
    user.userId,
  );

  if (!row) return jsonError(404, "key bundle not found");

  const bundleVersion = Number.parseInt(String((row as any).bundle_version ?? ""), 10);
  const bundleJson = String((row as any).bundle_json ?? "");

  let bundle: any;
  try {
    bundle = JSON.parse(bundleJson);
  } catch {
    return jsonError(500, "corrupt key bundle");
  }
  if (!bundle || typeof bundle !== "object") return jsonError(500, "corrupt key bundle");
  bundle.bundleVersion = bundleVersion;

  return jsonResponse(bundle);
}

async function putKeyBundle(request: Request, env: Env): Promise<Response> {
  const appCfg = loadConfig(request, env);
  const user = await authenticateApiRequest(env, appCfg.auth, request);

  const req = (await readJsonBody(request, BODY_LIMIT_BYTES)) as any;
  const expectedBundleVersion = Number.parseInt(String(req?.expectedBundleVersion ?? ""), 10);
  if (!Number.isFinite(expectedBundleVersion)) return jsonError(400, "invalid bundle");
  const bundle = req?.bundle;
  if (!bundle || typeof bundle !== "object") return jsonError(400, "invalid bundle");

  const row = await d1First(env, `SELECT bundle_version FROM key_bundles WHERE user_id = ?`, user.userId);
  const currentVersion = row ? Number.parseInt(String((row as any).bundle_version ?? ""), 10) : 0;

  if (expectedBundleVersion !== currentVersion) return jsonError(409, "bundle version mismatch");

  const nowMs = nowMsUtc();
  const newVersion = currentVersion + 1;
  bundle.bundleVersion = newVersion;
  bundle.updatedAtMsUtc = nowMs;

  let bundleJson: string;
  try {
    bundleJson = JSON.stringify(bundle);
  } catch {
    return jsonError(400, "invalid bundle");
  }

  await d1Run(
    env,
    `INSERT INTO key_bundles (user_id, bundle_version, bundle_json, updated_at_ms_utc)
     VALUES (?, ?, ?, ?)
     ON CONFLICT(user_id) DO UPDATE SET
       bundle_version = excluded.bundle_version,
       bundle_json = excluded.bundle_json,
       updated_at_ms_utc = excluded.updated_at_ms_utc`,
    user.userId,
    newVersion,
    bundleJson,
    nowMs,
  );

  return jsonResponse(bundle);
}

type Hlc = { wallTimeMsUtc: number; counter: number; deviceId: string };

type SyncRecordPayload = {
  type: string;
  recordId: string;
  hlc: Hlc;
  deletedAtMsUtc: number | null;
  schemaVersion: number;
  dekId: string;
  payloadAlgo: string;
  nonce: string;
  ciphertext: string;
};

function hlcIsNewer(a: Hlc, b: Hlc): boolean {
  if (a.wallTimeMsUtc !== b.wallTimeMsUtc) return a.wallTimeMsUtc > b.wallTimeMsUtc;
  if (a.counter !== b.counter) return a.counter > b.counter;
  return a.deviceId > b.deviceId;
}

function isAttachmentStagedType(type: string): boolean {
  return type === TYPE_TODO_ATTACHMENT || type === TYPE_TODO_ATTACHMENT_CHUNK;
}

function attachmentIdFromRecord(type: string, recordId: string): string | null {
  if (!recordId) return null;
  if (type === TYPE_TODO_ATTACHMENT || type === TYPE_TODO_ATTACHMENT_COMMIT) return recordId;
  if (type === TYPE_TODO_ATTACHMENT_CHUNK) return recordId.split(":", 1)[0] ?? null;
  return null;
}

function parseChunkIndex(recordId: string): number | null {
  const idx = recordId.split(":").pop();
  if (!idx) return null;
  const n = Number.parseInt(idx, 10);
  return Number.isFinite(n) ? n : null;
}

async function reserveServerSeqRange(
  env: Env,
  userId: number,
  count: number,
): Promise<{ firstSeq: number; lastSeq: number }> {
  if (count <= 0) return { firstSeq: 0, lastSeq: 0 };

  await d1Run(
    env,
    `INSERT INTO server_seq (user_id, next_seq)
     VALUES (?, 0)
     ON CONFLICT(user_id) DO NOTHING`,
    userId,
  );

  const seqRow = await d1First(
    env,
    `UPDATE server_seq
       SET next_seq = next_seq + ?
     WHERE user_id = ?
     RETURNING next_seq`,
    count,
    userId,
  );

  const lastSeq = Number.parseInt(String((seqRow as any)?.next_seq ?? ""), 10);
  if (!Number.isFinite(lastSeq)) throw dbError();
  const firstSeq = lastSeq - count + 1;
  return { firstSeq, lastSeq };
}

async function fetchExistingHlcs(
  env: Env,
  table: "records" | "staged_records",
  userId: number,
  byType: Map<string, string[]>,
): Promise<Map<string, Hlc>> {
  const existing = new Map<string, Hlc>();
  for (const [type, idsAll] of byType.entries()) {
    const ids = Array.from(new Set(idsAll));
    const chunkSize = D1_IN_CLAUSE_MAX_IDS;
    for (let i = 0; i < ids.length; i += chunkSize) {
      const chunk = ids.slice(i, i + chunkSize);
      const placeholders = chunk.map(() => "?").join(",");
      const sql = `SELECT record_id, hlc_wall_ms_utc, hlc_counter, hlc_device_id
                   FROM ${table}
                   WHERE user_id = ? AND type = ? AND record_id IN (${placeholders})`;
      const rows = await d1All(env, sql, userId, type, ...chunk);
      for (const row of (rows?.results ?? []) as any[]) {
        const recordId = String(row?.record_id ?? "");
        const wall = Number.parseInt(String(row?.hlc_wall_ms_utc ?? ""), 10);
        const counter = Number.parseInt(String(row?.hlc_counter ?? ""), 10);
        const deviceId = String(row?.hlc_device_id ?? "");
        existing.set(`${type}\n${recordId}`, {
          wallTimeMsUtc: Number.isFinite(wall) ? wall : 0,
          counter: Number.isFinite(counter) ? counter : 0,
          deviceId,
        });
      }
    }
  }
  return existing;
}

async function deleteStagedAttachment(env: Env, userId: number, attachmentId: string): Promise<void> {
  const pattern = `${attachmentId}:%`;
  await d1Run(
    env,
    `DELETE FROM staged_records
     WHERE user_id = ?
       AND (
         (type = ? AND record_id = ?)
         OR (type = ? AND record_id LIKE ?)
       )`,
    userId,
    TYPE_TODO_ATTACHMENT,
    attachmentId,
    TYPE_TODO_ATTACHMENT_CHUNK,
    pattern,
  );
}

async function upsertStagedRecords(
  env: Env,
  userId: number,
  records: SyncRecordPayload[],
  nowMs: number,
): Promise<void> {
  if (records.length === 0) return;

  const chunkSize = D1_STAGED_UPSERT_ROWS;
  for (let i = 0; i < records.length; i += chunkSize) {
    const chunk = records.slice(i, i + chunkSize);
    const valuesSql = chunk.map(() => "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)").join(",\n");
    const sql = `INSERT INTO staged_records (
      user_id, type, record_id,
      hlc_wall_ms_utc, hlc_counter, hlc_device_id,
      deleted_at_ms_utc,
      schema_version, dek_id,
      algo, nonce, ciphertext,
      updated_at_ms_utc
    ) VALUES
    ${valuesSql}
    ON CONFLICT(user_id, type, record_id) DO UPDATE SET
      hlc_wall_ms_utc = excluded.hlc_wall_ms_utc,
      hlc_counter = excluded.hlc_counter,
      hlc_device_id = excluded.hlc_device_id,
      deleted_at_ms_utc = excluded.deleted_at_ms_utc,
      schema_version = excluded.schema_version,
      dek_id = excluded.dek_id,
      algo = excluded.algo,
      nonce = excluded.nonce,
      ciphertext = excluded.ciphertext,
      updated_at_ms_utc = excluded.updated_at_ms_utc
    WHERE (excluded.hlc_wall_ms_utc, excluded.hlc_counter, excluded.hlc_device_id)
        > (staged_records.hlc_wall_ms_utc, staged_records.hlc_counter, staged_records.hlc_device_id)`;

    const binds: any[] = [];
    for (const r of chunk) {
      binds.push(
        userId,
        r.type,
        r.recordId,
        r.hlc.wallTimeMsUtc,
        r.hlc.counter,
        r.hlc.deviceId,
        r.deletedAtMsUtc,
        r.schemaVersion,
        r.dekId,
        r.payloadAlgo,
        r.nonce,
        r.ciphertext,
        nowMs,
      );
    }

    await d1Run(env, sql, ...binds);
  }
}

async function commitStagedAttachment(env: Env, userId: number, attachmentId: string): Promise<void> {
  const stagedMeta = await d1First(
    env,
    `SELECT
       type,
       record_id,
       hlc_wall_ms_utc,
       hlc_counter,
       hlc_device_id,
       deleted_at_ms_utc,
       schema_version,
       dek_id,
       algo,
       nonce,
       ciphertext
     FROM staged_records
     WHERE user_id = ? AND type = ? AND record_id = ?`,
    userId,
    TYPE_TODO_ATTACHMENT,
    attachmentId,
  );

  const pattern = `${attachmentId}:%`;
  const stagedChunks = await d1All(
    env,
    `SELECT
       type,
       record_id,
       hlc_wall_ms_utc,
       hlc_counter,
       hlc_device_id,
       deleted_at_ms_utc,
       schema_version,
       dek_id,
       algo,
       nonce,
       ciphertext
     FROM staged_records
     WHERE user_id = ? AND type = ? AND record_id LIKE ?`,
    userId,
    TYPE_TODO_ATTACHMENT_CHUNK,
    pattern,
  );

  const rows: SyncRecordPayload[] = [];
  if (stagedMeta) {
    const wall = Number.parseInt(String((stagedMeta as any)?.hlc_wall_ms_utc ?? ""), 10) || 0;
    const counter = Number.parseInt(String((stagedMeta as any)?.hlc_counter ?? ""), 10) || 0;
    const deviceId = String((stagedMeta as any)?.hlc_device_id ?? "");
    rows.push({
      type: String((stagedMeta as any)?.type ?? ""),
      recordId: String((stagedMeta as any)?.record_id ?? ""),
      hlc: { wallTimeMsUtc: wall, counter, deviceId },
      deletedAtMsUtc:
        (stagedMeta as any)?.deleted_at_ms_utc === null || (stagedMeta as any)?.deleted_at_ms_utc === undefined
          ? null
          : Number.parseInt(String((stagedMeta as any)?.deleted_at_ms_utc ?? ""), 10) || 0,
      schemaVersion: Number.parseInt(String((stagedMeta as any)?.schema_version ?? ""), 10) || 0,
      dekId: String((stagedMeta as any)?.dek_id ?? ""),
      payloadAlgo: String((stagedMeta as any)?.algo ?? ""),
      nonce: String((stagedMeta as any)?.nonce ?? ""),
      ciphertext: String((stagedMeta as any)?.ciphertext ?? ""),
    });
  }

  for (const row of (stagedChunks?.results ?? []) as any[]) {
    rows.push({
      type: String(row?.type ?? ""),
      recordId: String(row?.record_id ?? ""),
      hlc: {
        wallTimeMsUtc: Number.parseInt(String(row?.hlc_wall_ms_utc ?? ""), 10) || 0,
        counter: Number.parseInt(String(row?.hlc_counter ?? ""), 10) || 0,
        deviceId: String(row?.hlc_device_id ?? ""),
      },
      deletedAtMsUtc:
        row?.deleted_at_ms_utc === null || row?.deleted_at_ms_utc === undefined
          ? null
          : Number.parseInt(String(row?.deleted_at_ms_utc ?? ""), 10) || 0,
      schemaVersion: Number.parseInt(String(row?.schema_version ?? ""), 10) || 0,
      dekId: String(row?.dek_id ?? ""),
      payloadAlgo: String(row?.algo ?? ""),
      nonce: String(row?.nonce ?? ""),
      ciphertext: String(row?.ciphertext ?? ""),
    });
  }

  rows.sort((a, b) => {
    const aIsChunk = a.type === TYPE_TODO_ATTACHMENT_CHUNK;
    const bIsChunk = b.type === TYPE_TODO_ATTACHMENT_CHUNK;
    if (aIsChunk !== bIsChunk) return aIsChunk ? 1 : -1;
    if (!aIsChunk) return 0;
    const ai = parseChunkIndex(a.recordId) ?? Number.MAX_SAFE_INTEGER;
    const bi = parseChunkIndex(b.recordId) ?? Number.MAX_SAFE_INTEGER;
    return ai - bi;
  });

  if (rows.length === 0) return;

  const byType = new Map<string, string[]>();
  for (const r of rows) {
    const list = byType.get(r.type);
    if (list) list.push(r.recordId);
    else byType.set(r.type, [r.recordId]);
  }
  const existing = await fetchExistingHlcs(env, "records", userId, byType);

  const toApply: SyncRecordPayload[] = [];
  for (const r of rows) {
    const cur = existing.get(`${r.type}\n${r.recordId}`) ?? null;
    if (!cur || hlcIsNewer(r.hlc, cur)) toApply.push(r);
  }

  const nowMs = nowMsUtc();
  if (toApply.length > 0) {
    const { firstSeq } = await reserveServerSeqRange(env, userId, toApply.length);

    const appliedChunkSize = D1_RECORDS_UPSERT_ROWS;
    for (let i = 0; i < toApply.length; i += appliedChunkSize) {
      const chunk = toApply.slice(i, i + appliedChunkSize);
      const valuesSql = chunk.map(() => "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)").join(",\n");
      const sql = `INSERT INTO records (
        user_id, type, record_id,
        hlc_wall_ms_utc, hlc_counter, hlc_device_id,
        deleted_at_ms_utc,
        schema_version, dek_id,
        algo, nonce, ciphertext,
        server_seq, updated_at_ms_utc
      ) VALUES
      ${valuesSql}
      ON CONFLICT(user_id, type, record_id) DO UPDATE SET
        hlc_wall_ms_utc = excluded.hlc_wall_ms_utc,
        hlc_counter = excluded.hlc_counter,
        hlc_device_id = excluded.hlc_device_id,
        deleted_at_ms_utc = excluded.deleted_at_ms_utc,
        schema_version = excluded.schema_version,
        dek_id = excluded.dek_id,
        algo = excluded.algo,
        nonce = excluded.nonce,
        ciphertext = excluded.ciphertext,
        server_seq = excluded.server_seq,
        updated_at_ms_utc = excluded.updated_at_ms_utc
      WHERE (excluded.hlc_wall_ms_utc, excluded.hlc_counter, excluded.hlc_device_id)
          > (records.hlc_wall_ms_utc, records.hlc_counter, records.hlc_device_id)`;

      const binds: any[] = [];
      for (let j = 0; j < chunk.length; j++) {
        const r = chunk[j]!;
        const serverSeq = firstSeq + i + j;
        binds.push(
          userId,
          r.type,
          r.recordId,
          r.hlc.wallTimeMsUtc,
          r.hlc.counter,
          r.hlc.deviceId,
          r.deletedAtMsUtc,
          r.schemaVersion,
          r.dekId,
          r.payloadAlgo,
          r.nonce,
          r.ciphertext,
          serverSeq,
          nowMs,
        );
      }

      await d1Run(env, sql, ...binds);
    }
  }

  await deleteStagedAttachment(env, userId, attachmentId);
}

async function compactCommittedAttachmentChunks(
  env: Env,
  userId: number,
  attachmentId: string,
  deletedAtMsUtc: number,
): Promise<void> {
  const nowMs = nowMsUtc();
  const pattern = `${attachmentId}:%`;

  const rows = await d1All(
    env,
    `SELECT
       record_id,
       hlc_wall_ms_utc,
       deleted_at_ms_utc,
       LENGTH(nonce) AS nonce_len,
       LENGTH(ciphertext) AS ciphertext_len
     FROM records
     WHERE user_id = ? AND type = ? AND record_id LIKE ?`,
    userId,
    TYPE_TODO_ATTACHMENT_CHUNK,
    pattern,
  );

  const results = (rows?.results ?? []) as any[];
  const toCompact: { recordId: string; existingWall: number }[] = [];
  for (const row of results) {
    const recordId = String(row?.record_id ?? "");
    const existingWall = Number.parseInt(String(row?.hlc_wall_ms_utc ?? ""), 10) || 0;
    const existingDeleted =
      row?.deleted_at_ms_utc === null || row?.deleted_at_ms_utc === undefined
        ? null
        : Number.parseInt(String(row?.deleted_at_ms_utc ?? ""), 10) || 0;
    const nonceLen = Number.parseInt(String(row?.nonce_len ?? ""), 10) || 0;
    const ciphertextLen = Number.parseInt(String(row?.ciphertext_len ?? ""), 10) || 0;

    if (existingDeleted && nonceLen === 0 && ciphertextLen === 0) continue;
    toCompact.push({ recordId, existingWall });
  }

  if (toCompact.length === 0) return;

  const { firstSeq } = await reserveServerSeqRange(env, userId, toCompact.length);
  for (let i = 0; i < toCompact.length; i++) {
    const row = toCompact[i]!;
    const serverSeq = firstSeq + i;
    const newWall = Math.max(row.existingWall, nowMs) + 1;
    await d1Run(
      env,
      `UPDATE records
       SET hlc_wall_ms_utc = ?,
           hlc_counter = 0,
           hlc_device_id = 'server',
           deleted_at_ms_utc = ?,
           nonce = '',
           ciphertext = '',
           server_seq = ?,
           updated_at_ms_utc = ?
       WHERE user_id = ? AND type = ? AND record_id = ?`,
      newWall,
      deletedAtMsUtc,
      serverSeq,
      nowMs,
      userId,
      TYPE_TODO_ATTACHMENT_CHUNK,
      row.recordId,
    );
  }
}

async function pushSync(request: Request, env: Env): Promise<Response> {
  const appCfg = loadConfig(request, env);
  const user = await authenticateApiRequest(env, appCfg.auth, request);

  const nowMs = nowMsUtc();

  const body = (await readJsonBody(request, BODY_LIMIT_BYTES)) as any;
  const recordsIn = body?.records;
  if (!Array.isArray(recordsIn)) return jsonError(400, "invalid json");

  if (recordsIn.length > appCfg.maxPushRecords) return jsonError(400, "too many records");

  type Rec = {
    type: SyncRecordPayload["type"];
    recordId: SyncRecordPayload["recordId"];
    hlc: SyncRecordPayload["hlc"];
    deletedAtMsUtc: SyncRecordPayload["deletedAtMsUtc"];
    schemaVersion: SyncRecordPayload["schemaVersion"];
    dekId: SyncRecordPayload["dekId"];
    payloadAlgo: SyncRecordPayload["payloadAlgo"];
    nonce: SyncRecordPayload["nonce"];
    ciphertext: SyncRecordPayload["ciphertext"];
    tooLarge: boolean;
  };

  const parsed: Rec[] = [];
  const byTypeCommitted = new Map<string, string[]>();
  const byTypeStaged = new Map<string, string[]>();
  const attachmentIdsToCheckDeleted = new Set<string>();

  for (const r of recordsIn as any[]) {
    const type = String(r?.type ?? "");
    const recordId = String(r?.recordId ?? "");
    const nonce = String(r?.nonce ?? "");
    const ciphertext = String(r?.ciphertext ?? "");
    const tooLarge = nonce.length > MAX_RECORD_B64_LEN || ciphertext.length > MAX_RECORD_B64_LEN;

    const hlcWall = Number.parseInt(String(r?.hlc?.wallTimeMsUtc ?? ""), 10);
    const hlcCounter = Number.parseInt(String(r?.hlc?.counter ?? ""), 10);
    const hlcDeviceId = String(r?.hlc?.deviceId ?? "");

    const deletedAt = r?.deletedAtMsUtc;
    const deletedAtMsUtc =
      deletedAt === null || deletedAt === undefined ? null : Number.parseInt(String(deletedAt), 10);

    const schemaVersion = Number.parseInt(String(r?.schemaVersion ?? ""), 10) || 0;
    const dekId = String(r?.dekId ?? "");
    const payloadAlgo = String(r?.payloadAlgo ?? "");

    const rec: Rec = {
      type,
      recordId,
      hlc: {
        wallTimeMsUtc: Number.isFinite(hlcWall) ? hlcWall : 0,
        counter: Number.isFinite(hlcCounter) ? hlcCounter : 0,
        deviceId: hlcDeviceId,
      },
      deletedAtMsUtc: Number.isFinite(deletedAtMsUtc as number) ? (deletedAtMsUtc as number) : null,
      schemaVersion,
      dekId,
      payloadAlgo,
      nonce,
      ciphertext,
      tooLarge,
    };
    parsed.push(rec);

    if (!tooLarge && type !== TYPE_TODO_ATTACHMENT_COMMIT) {
      const list = byTypeCommitted.get(type);
      if (list) list.push(recordId);
      else byTypeCommitted.set(type, [recordId]);

      if (isAttachmentStagedType(type)) {
        const stagedList = byTypeStaged.get(type);
        if (stagedList) stagedList.push(recordId);
        else byTypeStaged.set(type, [recordId]);
      }
    }

    const attachmentId = attachmentIdFromRecord(type, recordId);
    if (attachmentId && isAttachmentStagedType(type) && rec.deletedAtMsUtc === null) {
      attachmentIdsToCheckDeleted.add(attachmentId);
    }
    if (attachmentId && type === TYPE_TODO_ATTACHMENT_COMMIT && rec.deletedAtMsUtc === null) {
      attachmentIdsToCheckDeleted.add(attachmentId);
    }
  }

  const attachmentDeleted = new Map<string, number>();
  const attachments = Array.from(attachmentIdsToCheckDeleted);
  const deletedChunkSize = D1_IN_CLAUSE_MAX_IDS;
  for (let i = 0; i < attachments.length; i += deletedChunkSize) {
    const chunk = attachments.slice(i, i + deletedChunkSize);
    const placeholders = chunk.map(() => "?").join(",");
    const sql = `SELECT record_id, deleted_at_ms_utc
                 FROM records
                 WHERE user_id = ? AND type = ? AND record_id IN (${placeholders})`;
    const rows = await d1All(env, sql, user.userId, TYPE_TODO_ATTACHMENT, ...chunk);
    for (const row of (rows?.results ?? []) as any[]) {
      const recordId = String(row?.record_id ?? "");
      const deletedAt =
        row?.deleted_at_ms_utc === null || row?.deleted_at_ms_utc === undefined
          ? null
          : Number.parseInt(String(row?.deleted_at_ms_utc ?? ""), 10) || 0;
      if (deletedAt && deletedAt > 0) attachmentDeleted.set(recordId, deletedAt);
    }
  }

  // Fetch existing HLCs in batches to reduce query count.
  const existingCommitted = await fetchExistingHlcs(env, "records", user.userId, byTypeCommitted);
  const existingStaged = await fetchExistingHlcs(env, "staged_records", user.userId, byTypeStaged);

  const accepted: { type: string; recordId: string; serverSeq: number }[] = [];
  const rejected: { type: string; recordId: string; reason: string }[] = [];

  const commitRequests: { attachmentId: string; deletedAtMsUtc: number | null }[] = [];
  const deletedAttachmentsInPush = new Set<string>();
  const stagedUpserts = new Map<string, SyncRecordPayload>();
  const acceptedInput: Rec[] = [];

  for (const r of parsed) {
    if (r.tooLarge) {
      rejected.push({ type: r.type, recordId: r.recordId, reason: "record_too_large" });
      continue;
    }

    if (r.type === TYPE_TODO_ATTACHMENT_COMMIT) {
      commitRequests.push({ attachmentId: r.recordId, deletedAtMsUtc: r.deletedAtMsUtc });
      continue;
    }

    const isStagedType = isAttachmentStagedType(r.type);
    if (isStagedType && r.deletedAtMsUtc === null) {
      const attachmentId = attachmentIdFromRecord(r.type, r.recordId);
      if (attachmentId && (attachmentDeleted.has(attachmentId) || deletedAttachmentsInPush.has(attachmentId))) {
        rejected.push({ type: r.type, recordId: r.recordId, reason: "attachment_deleted" });
        continue;
      }
    }

    const key = `${r.type}\n${r.recordId}`;
    const committedHlc = existingCommitted.get(key) ?? null;
    const stagedHlc = !committedHlc && isStagedType ? existingStaged.get(key) ?? null : null;
    const cur = committedHlc ?? stagedHlc;

    if (cur && !hlcIsNewer(r.hlc, cur)) {
      rejected.push({ type: r.type, recordId: r.recordId, reason: "older_hlc" });
      continue;
    }

    // If the attachment metadata is tombstoned in `records` within this request,
    // subsequent meta/chunk uploads must be rejected to avoid recreating staged data.
    if (r.type === TYPE_TODO_ATTACHMENT && r.deletedAtMsUtc !== null && committedHlc) {
      const attachmentId = r.recordId;
      if (attachmentId) deletedAttachmentsInPush.add(attachmentId);
    }

    if (isStagedType && !committedHlc) {
      // For attachments/chunks, a tombstone before commit should simply remove any staged data and
      // remain invisible to other devices.
      if (r.deletedAtMsUtc !== null) {
        if (r.type === TYPE_TODO_ATTACHMENT) {
          const attachmentId = r.recordId;
          if (attachmentId) {
            await deleteStagedAttachment(env, user.userId, attachmentId);
            const prefixChunk = `${TYPE_TODO_ATTACHMENT_CHUNK}\n${attachmentId}:`;
            const toDelete: string[] = [];
            for (const k of stagedUpserts.keys()) {
              if (k === `${TYPE_TODO_ATTACHMENT}\n${attachmentId}` || k.startsWith(prefixChunk)) {
                toDelete.push(k);
              }
            }
            for (const k of toDelete) stagedUpserts.delete(k);
          }
          accepted.push({ type: r.type, recordId: r.recordId, serverSeq: 0 });
          continue;
        }

        if (r.type === TYPE_TODO_ATTACHMENT_CHUNK) {
          await d1Run(
            env,
            `DELETE FROM staged_records WHERE user_id = ? AND type = ? AND record_id = ?`,
            user.userId,
            r.type,
            r.recordId,
          );
          stagedUpserts.delete(key);
          accepted.push({ type: r.type, recordId: r.recordId, serverSeq: 0 });
          continue;
        }
      }

      stagedUpserts.set(key, {
        type: r.type,
        recordId: r.recordId,
        hlc: r.hlc,
        deletedAtMsUtc: r.deletedAtMsUtc,
        schemaVersion: r.schemaVersion,
        dekId: r.dekId,
        payloadAlgo: r.payloadAlgo,
        nonce: r.nonce,
        ciphertext: r.ciphertext,
      });

      accepted.push({ type: r.type, recordId: r.recordId, serverSeq: 0 });
      continue;
    }

    acceptedInput.push(r);
  }

  await upsertStagedRecords(env, user.userId, Array.from(stagedUpserts.values()), nowMs);

  if (acceptedInput.length > 0) {
    const { firstSeq } = await reserveServerSeqRange(env, user.userId, acceptedInput.length);

    const acceptedMeta: { type: string; recordId: string; serverSeq: number; deletedAtMsUtc: number | null }[] = [];
    for (let i = 0; i < acceptedInput.length; i++) {
      const serverSeq = firstSeq + i;
      acceptedMeta.push({
        type: acceptedInput[i]!.type,
        recordId: acceptedInput[i]!.recordId,
        serverSeq,
        deletedAtMsUtc: acceptedInput[i]!.deletedAtMsUtc,
      });
    }

    // Upsert in chunks with RETURNING to detect concurrent HLC races.
    const applied = new Set<string>();
    const chunkSize = D1_RECORDS_UPSERT_ROWS;
    for (let i = 0; i < acceptedInput.length; i += chunkSize) {
      const chunk = acceptedInput.slice(i, i + chunkSize);
      const chunkMeta = acceptedMeta.slice(i, i + chunkSize);

      const valuesSql = chunk.map(() => "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)").join(",\n");
      const sql = `INSERT INTO records (
        user_id, type, record_id,
        hlc_wall_ms_utc, hlc_counter, hlc_device_id,
        deleted_at_ms_utc,
        schema_version, dek_id,
        algo, nonce, ciphertext,
        server_seq, updated_at_ms_utc
      ) VALUES
      ${valuesSql}
      ON CONFLICT(user_id, type, record_id) DO UPDATE SET
        hlc_wall_ms_utc = excluded.hlc_wall_ms_utc,
        hlc_counter = excluded.hlc_counter,
        hlc_device_id = excluded.hlc_device_id,
        deleted_at_ms_utc = excluded.deleted_at_ms_utc,
        schema_version = excluded.schema_version,
        dek_id = excluded.dek_id,
        algo = excluded.algo,
        nonce = excluded.nonce,
        ciphertext = excluded.ciphertext,
        server_seq = excluded.server_seq,
        updated_at_ms_utc = excluded.updated_at_ms_utc
      WHERE (excluded.hlc_wall_ms_utc, excluded.hlc_counter, excluded.hlc_device_id)
          > (records.hlc_wall_ms_utc, records.hlc_counter, records.hlc_device_id)
      RETURNING type, record_id`;

      const binds: any[] = [];
      for (let j = 0; j < chunk.length; j++) {
        const r = chunk[j]!;
        const m = chunkMeta[j]!;
        binds.push(
          user.userId,
          r.type,
          r.recordId,
          r.hlc.wallTimeMsUtc,
          r.hlc.counter,
          r.hlc.deviceId,
          r.deletedAtMsUtc,
          r.schemaVersion,
          r.dekId,
          r.payloadAlgo,
          r.nonce,
          r.ciphertext,
          m.serverSeq,
          nowMs,
        );
      }

      const res = await d1All(env, sql, ...binds);
      for (const row of (res?.results ?? []) as any[]) {
        const type = String(row?.type ?? "");
        const recordId = String(row?.record_id ?? "");
        applied.add(`${type}\n${recordId}`);
      }
    }

    for (const m of acceptedMeta) {
      const key = `${m.type}\n${m.recordId}`;
      if (applied.has(key)) {
        accepted.push({ type: m.type, recordId: m.recordId, serverSeq: m.serverSeq });

        if (m.type === TYPE_TODO_ATTACHMENT && m.deletedAtMsUtc !== null) {
          attachmentDeleted.set(m.recordId, m.deletedAtMsUtc);
          await deleteStagedAttachment(env, user.userId, m.recordId);
          await compactCommittedAttachmentChunks(env, user.userId, m.recordId, m.deletedAtMsUtc ?? nowMs);
        }
      } else {
        rejected.push({ type: m.type, recordId: m.recordId, reason: "older_hlc" });
      }
    }
  }

  for (const c of commitRequests) {
    const attachmentId = c.attachmentId;
    if (c.deletedAtMsUtc !== null) {
      accepted.push({ type: TYPE_TODO_ATTACHMENT_COMMIT, recordId: attachmentId, serverSeq: 0 });
      continue;
    }

    const deletedRow = await d1First(
      env,
      `SELECT deleted_at_ms_utc
       FROM records
       WHERE user_id = ? AND type = ? AND record_id = ?`,
      user.userId,
      TYPE_TODO_ATTACHMENT,
      attachmentId,
    );
    const committedDeleted =
      (deletedRow as any)?.deleted_at_ms_utc === null || (deletedRow as any)?.deleted_at_ms_utc === undefined
        ? null
        : Number.parseInt(String((deletedRow as any)?.deleted_at_ms_utc ?? ""), 10) || 0;
    if (committedDeleted && committedDeleted > 0) {
      rejected.push({ type: TYPE_TODO_ATTACHMENT_COMMIT, recordId: attachmentId, reason: "attachment_deleted" });
      continue;
    }

    const hasCommittedMeta = await d1First(
      env,
      `SELECT 1 AS ok
       FROM records
       WHERE user_id = ? AND type = ? AND record_id = ? AND deleted_at_ms_utc IS NULL
       LIMIT 1`,
      user.userId,
      TYPE_TODO_ATTACHMENT,
      attachmentId,
    );

    const hasStagedMeta = await d1First(
      env,
      `SELECT 1 AS ok FROM staged_records WHERE user_id = ? AND type = ? AND record_id = ? LIMIT 1`,
      user.userId,
      TYPE_TODO_ATTACHMENT,
      attachmentId,
    );

    if (!hasCommittedMeta && !hasStagedMeta) {
      rejected.push({
        type: TYPE_TODO_ATTACHMENT_COMMIT,
        recordId: attachmentId,
        reason: "missing_attachment_meta",
      });
      continue;
    }

    await commitStagedAttachment(env, user.userId, attachmentId);
    accepted.push({ type: TYPE_TODO_ATTACHMENT_COMMIT, recordId: attachmentId, serverSeq: 0 });
  }

  return jsonResponse({ accepted, rejected });
}

async function pullSync(request: Request, env: Env): Promise<Response> {
  const appCfg = loadConfig(request, env);
  const user = await authenticateApiRequest(env, appCfg.auth, request);

  const url = new URL(request.url);
  const since = Math.max(0, Number.parseInt(url.searchParams.get("since") ?? "0", 10) || 0);
  const limitRaw = Number.parseInt(url.searchParams.get("limit") ?? "200", 10) || 200;
  const limit = Math.min(MAX_PULL_LIMIT, Math.max(1, limitRaw));
  const excludeDeviceId = (url.searchParams.get("excludeDeviceId") ?? "").trim() || null;

  const rows = await d1All(
    env,
    `SELECT
       type,
       record_id,
       hlc_wall_ms_utc,
       hlc_counter,
       hlc_device_id,
       deleted_at_ms_utc,
       schema_version,
       dek_id,
       algo,
       nonce,
       ciphertext,
       server_seq
     FROM records
     WHERE user_id = ? AND server_seq > ? AND (? IS NULL OR hlc_device_id != ?)
     ORDER BY server_seq ASC
     LIMIT ?`,
    user.userId,
    since,
    excludeDeviceId,
    excludeDeviceId,
    limit,
  );

  const results = (rows?.results ?? []) as any[];
  if (results.length === 0) {
    const headRow = await d1First(
      env,
      `SELECT COALESCE(MAX(server_seq), 0) AS head FROM records WHERE user_id = ?`,
      user.userId,
    );
    const head = Number.parseInt(String((headRow as any)?.head ?? "0"), 10) || 0;
    return jsonResponse({ records: [], nextSince: head });
  }

  let nextSince = since;
  const out: any[] = new Array(results.length);
  for (let i = 0; i < results.length; i++) {
    const row = results[i]!;
    const serverSeq = Number.parseInt(String(row?.server_seq ?? ""), 10) || 0;
    if (serverSeq > nextSince) nextSince = serverSeq;
    out[i] = {
      type: String(row?.type ?? ""),
      recordId: String(row?.record_id ?? ""),
      hlc: {
        wallTimeMsUtc: Number.parseInt(String(row?.hlc_wall_ms_utc ?? ""), 10) || 0,
        counter: Number.parseInt(String(row?.hlc_counter ?? ""), 10) || 0,
        deviceId: String(row?.hlc_device_id ?? ""),
      },
      deletedAtMsUtc: row?.deleted_at_ms_utc === null || row?.deleted_at_ms_utc === undefined ? null : (Number.parseInt(String(row?.deleted_at_ms_utc ?? ""), 10) || 0),
      schemaVersion: Number.parseInt(String(row?.schema_version ?? ""), 10) || 0,
      dekId: String(row?.dek_id ?? ""),
      payloadAlgo: String(row?.algo ?? ""),
      nonce: String(row?.nonce ?? ""),
      ciphertext: String(row?.ciphertext ?? ""),
    };
  }

  return jsonResponse({ records: out, nextSince });
}

async function health(): Promise<Response> {
  return textResponse("ok");
}

function notFound(path: string): Response {
  if (path.startsWith("/v1/")) return jsonError(404, "not found");
  return textResponse("not found", 404);
}

const routes = new Map<string, (request: Request, env: Env) => Promise<Response>>([
  ["GET /v1/health", async (r) => health()],
  ["GET /v1/auth/providers", authProviders],
  ["GET /v1/auth/start", authStart],
  ["GET /v1/auth/web/start", authWebStart],
  ["GET /v1/auth/callback", authCallback],
  ["POST /v1/auth/exchange", authExchange],
  ["POST /v1/auth/refresh", authRefresh],
  ["POST /v1/auth/logout", authLogout],
  ["GET /v1/key-bundle", getKeyBundle],
  ["PUT /v1/key-bundle", putKeyBundle],
  ["POST /v1/sync/push", pushSync],
  ["GET /v1/sync/pull", pullSync],
]);

export default {
  async fetch(request: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const cfg = loadConfig(request, env);
    try {
      const key = `${request.method.toUpperCase()} ${url.pathname}`;

      if (request.method.toUpperCase() === "OPTIONS" && shouldApplyCors(url.pathname)) {
        const corsHeaders = buildCorsHeaders(request, cfg.cors);
        if (!corsHeaders) return new Response(null, { status: 204 });
        return new Response(null, { status: 204, headers: corsHeaders });
      }

      const handler = routes.get(key);
      if (!handler) return withCors(request, cfg.cors, notFound(url.pathname));
      const resp = await handler(request, env);
      return shouldApplyCors(url.pathname) ? withCors(request, cfg.cors, resp) : resp;
    } catch (e) {
      if (e instanceof Response) {
        return shouldApplyCors(url.pathname) ? withCors(request, cfg.cors, e) : e;
      }
      console.error("Unhandled error", { method: request.method, path: url.pathname }, e);
      const resp = jsonError(500, "internal error");
      return shouldApplyCors(url.pathname) ? withCors(request, cfg.cors, resp) : resp;
    }
  },
};
