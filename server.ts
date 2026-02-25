import tls from 'node:tls'
import { randomBytes } from 'node:crypto'
import { Database } from 'bun:sqlite'
import Stripe from 'stripe'

const PORT = 3000
const MAX_REDIRECTS = 5
const DB_PATH = '/root/opus-orchestrator/workspace/opus-api/pulse.db'
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || ''
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || ''
const STRIPE_PRICE_ID = process.env.STRIPE_PRICE_ID || ''
const stripe = STRIPE_SECRET_KEY ? new Stripe(STRIPE_SECRET_KEY) : null

const corsHeaders: Record<string, string> = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, X-API-Key',
}

type CorsInit = Record<string, string>

type SslInfo = {
  valid: boolean
  issuer: string | null
  expiresAt: string | null
}

type CheckPayload = {
  url: string
  timestamp: string
  responseTimeMs: number
  statusCode: number
  headers: Record<string, string>
  ssl: SslInfo
  redirects: string[]
  error?: string
}

type ApiKeyRow = {
  id: number
  key: string
  email: string
  tier: string
  created_at: string
  checks_today: number
  last_reset: string
}

type RateLimitRow = {
  ip: string
  checks_today: number
  last_reset: string
}

type MonitorRow = {
  id: number
  api_key: string
  url: string
  interval_minutes: number
  last_check: string | null
  status: string
  created_at: string
}

const db = new Database(DB_PATH)

db.exec(`
  CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY,
    key TEXT UNIQUE,
    email TEXT UNIQUE,
    tier TEXT DEFAULT 'free',
    created_at TEXT,
    checks_today INTEGER DEFAULT 0,
    last_reset TEXT
  );

  CREATE TABLE IF NOT EXISTS checks (
    id INTEGER PRIMARY KEY,
    api_key TEXT,
    ip TEXT,
    url TEXT,
    status_code INTEGER,
    response_time_ms INTEGER,
    created_at TEXT
  );

  CREATE TABLE IF NOT EXISTS rate_limits (
    ip TEXT PRIMARY KEY,
    checks_today INTEGER DEFAULT 0,
    last_reset TEXT
  );

  CREATE TABLE IF NOT EXISTS monitors (
    id INTEGER PRIMARY KEY,
    api_key TEXT NOT NULL,
    url TEXT NOT NULL,
    interval_minutes INTEGER DEFAULT 5,
    last_check TEXT,
    status TEXT DEFAULT 'active',
    created_at TEXT
  );
`)

const findApiKeyByEmailStmt = db.prepare<
  ApiKeyRow,
  [string]
>('SELECT * FROM api_keys WHERE email = ?')
const findApiKeyByKeyStmt = db.prepare<ApiKeyRow, [string]>('SELECT * FROM api_keys WHERE "key" = ?')
const insertApiKeyStmt = db.prepare(
  `INSERT INTO api_keys ("key", email, tier, created_at, checks_today, last_reset)
   VALUES (?, ?, ?, ?, 0, ?)`
)
const updateApiKeyChecksStmt = db.prepare('UPDATE api_keys SET checks_today = checks_today + 1 WHERE "key" = ?')
const updateApiKeyResetStmt = db.prepare('UPDATE api_keys SET checks_today = 0, last_reset = ? WHERE "key" = ?')

const findRateLimitByIpStmt = db.prepare<RateLimitRow, [string]>('SELECT * FROM rate_limits WHERE ip = ?')
const insertRateLimitStmt = db.prepare('INSERT INTO rate_limits (ip, checks_today, last_reset) VALUES (?, 0, ?)')
const updateRateLimitChecksStmt = db.prepare('UPDATE rate_limits SET checks_today = checks_today + 1 WHERE ip = ?')
const updateRateLimitResetStmt = db.prepare('UPDATE rate_limits SET checks_today = 0, last_reset = ? WHERE ip = ?')

const insertCheckStmt = db.prepare(
  'INSERT INTO checks (api_key, ip, url, status_code, response_time_ms, created_at) VALUES (?, ?, ?, ?, ?, ?)'
)
const getHistoryStmt = db.prepare(
  'SELECT id, api_key, ip, url, status_code, response_time_ms, created_at FROM checks WHERE api_key = ? ORDER BY id DESC LIMIT 50'
)
const updateApiKeyTierStmt = db.prepare('UPDATE api_keys SET tier = ? WHERE email = ?')
const insertMonitorStmt = db.prepare(
  `INSERT INTO monitors (api_key, url, interval_minutes, last_check, status, created_at)
   VALUES (?, ?, ?, NULL, 'active', ?)`
)
const getMonitorsStmt = db.prepare<MonitorRow, [string]>(
  "SELECT id, api_key, url, interval_minutes, last_check, status, created_at FROM monitors WHERE api_key = ? AND status = 'active'",
)
const deleteMonitorStmt = db.prepare(
  'UPDATE monitors SET status = \'deleted\' WHERE id = ? AND api_key = ?',
)
const getDueMonitorsStmt = db.prepare<
  Pick<MonitorRow, 'id' | 'api_key' | 'url' | 'interval_minutes' | 'last_check'>,
  []
>("SELECT id, api_key, url, interval_minutes, last_check FROM monitors WHERE status = 'active'")

function toISOStringNow(): string {
  return new Date().toISOString()
}

function utcDateKey(): string {
  return new Date().toISOString().slice(0, 10)
}

function utcMidnightReset(): string {
  const now = new Date()
  const reset = new Date(
    Date.UTC(
      now.getUTCFullYear(),
      now.getUTCMonth(),
      now.getUTCDate() + 1,
      0,
      0,
      0,
      0,
    ),
  )

  return reset.toISOString()
}

function secondsUntilMidnightUtc(): number {
  return Math.max(0, Math.ceil((Date.parse(utcMidnightReset()) - Date.now()) / 1000))
}

function withCors(body: BodyInit | null, init: ResponseInit = {}): Response {
  const headers = new Headers(init.headers)
  for (const [key, value] of Object.entries(corsHeaders)) {
    headers.set(key, value)
  }

  return new Response(body, {
    ...init,
    headers,
  })
}

function withJson(body: unknown, init: ResponseInit = {}): Response {
  const headers = new Headers(init.headers)
  headers.set('Content-Type', 'application/json')

  return withCors(JSON.stringify(body), {
    ...init,
    headers,
  })
}

function isRedirect(status: number): boolean {
  return status >= 300 && status < 400
}

function normalizeUrl(input: string): string {
  const trimmed = input.trim()
  if (/^https?:\/\//i.test(trimmed)) {
    return trimmed
  }
  return `https://${trimmed}`
}

function headerObject(headers: Headers): Record<string, string> {
  const entries: Record<string, string> = {}
  for (const [key, value] of headers.entries()) {
    entries[key] = value
  }
  return entries
}

function extractIssuer(cert: any): string | null {
  const issuer = cert?.issuer
  if (!issuer || typeof issuer !== 'object') return null

  if (typeof issuer.O === 'string' && issuer.O.trim()) return issuer.O
  if (typeof issuer.CN === 'string' && issuer.CN.trim()) return issuer.CN
  if (typeof issuer.organizationName === 'string' && issuer.organizationName.trim()) {
    return issuer.organizationName
  }

  const candidateKeys = ['O', 'CN', 'organizationName', 'organization'] as const
  for (const key of candidateKeys) {
    const value = (issuer as Record<string, unknown>)[key]
    if (typeof value === 'string' && value.trim()) {
      return value
    }
  }

  const fallback = JSON.stringify(issuer)
  return fallback.length > 0 ? fallback : null
}

function getSslInfo(url: URL): Promise<SslInfo> {
  return new Promise((resolve) => {
    if (url.protocol !== 'https:') {
      resolve({ valid: false, issuer: null, expiresAt: null })
      return
    }

    const host = url.hostname
    const port = url.port ? Number(url.port) : 443
    let settled = false

    const finalize = (value: SslInfo) => {
      if (settled) return
      settled = true
      socket.end()
      resolve(value)
    }

    const socket = tls.connect({
      host,
      port,
      servername: host,
      rejectUnauthorized: false,
    })

    const onSecure = () => {
      try {
        const cert = socket.getPeerCertificate(true) as any
        if (!cert || Object.keys(cert).length === 0) {
          finalize({ valid: false, issuer: null, expiresAt: null })
          return
        }

        let valid = true
        const expiry = cert.valid_to ? new Date(cert.valid_to) : null
        if (!expiry || Number.isNaN(expiry.getTime()) || expiry.getTime() <= Date.now()) {
          valid = false
        }

        try {
          tls.checkServerIdentity(host, cert)
        } catch {
          valid = false
        }

        finalize({
          valid,
          issuer: extractIssuer(cert),
          expiresAt: cert.valid_to ?? null,
        })
      } catch {
        finalize({ valid: false, issuer: null, expiresAt: null })
      }
    }

    socket.once('secureConnect', onSecure)

    socket.once('error', () => {
      finalize({ valid: false, issuer: null, expiresAt: null })
    })

    socket.setTimeout(5000, () => {
      finalize({ valid: false, issuer: null, expiresAt: null })
      socket.destroy(new Error('SSL timeout'))
    })
  })
}

async function checkUrl(inputUrl: string): Promise<CheckPayload> {
  const started = Date.now()
  const timestamp = toISOStringNow()
  const result: CheckPayload = {
    url: '',
    timestamp,
    responseTimeMs: 0,
    statusCode: 0,
    headers: {},
    ssl: { valid: false, issuer: null, expiresAt: null },
    redirects: [],
  }

  try {
    const normalized = normalizeUrl(inputUrl)
    let current = new URL(normalized)
    let response: Response | null = null

    for (let hops = 0; hops <= MAX_REDIRECTS; hops += 1) {
      response = await fetch(current.toString(), {
        method: 'GET',
        redirect: 'manual',
      })

      if (isRedirect(response.status)) {
        const location = response.headers.get('location')
        if (!location) {
          throw new Error('Redirect response missing Location header')
        }

        current = new URL(location, current)
        result.redirects.push(current.toString())

        if (hops === MAX_REDIRECTS) {
          throw new Error(`Too many redirects (max ${MAX_REDIRECTS})`)
        }

        continue
      }

      break
    }

    if (!response) {
      throw new Error('No response received')
    }

    result.url = current.toString()
    result.statusCode = response.status
    result.headers = headerObject(response.headers)
    result.responseTimeMs = Date.now() - started
    result.ssl = await getSslInfo(current)

    return result
  } catch (error) {
    result.error = error instanceof Error ? error.message : 'Unknown error'
    result.responseTimeMs = Date.now() - started
    if (!result.url) result.url = normalizeUrl(inputUrl)
    return result
  }
}

function getClientIp(request: Request): string {
  const forwarded = request.headers.get('x-forwarded-for')
  if (forwarded) {
    const parts = forwarded.split(',').map((value) => value.trim()).filter(Boolean)
    if (parts.length > 0) return parts[0]
  }

  return (
    request.headers.get('x-real-ip')
    || request.headers.get('cf-connecting-ip')
    || 'unknown'
  )
}

function getApiKeyByEmail(email: string): ApiKeyRow | null {
  return findApiKeyByEmailStmt.get(email) as ApiKeyRow | null
}

function getApiKeyByKey(apiKey: string): ApiKeyRow | null {
  return findApiKeyByKeyStmt.get(apiKey) as ApiKeyRow | null
}

function getOrCreateApiKey(email: string): { apiKey: string; tier: string } {
  const normalizedEmail = email.trim().toLowerCase()
  const existing = getApiKeyByEmail(normalizedEmail)
  if (existing) {
    return { apiKey: existing.key, tier: existing.tier || 'free' }
  }

  const now = toISOStringNow()
  const today = utcDateKey()
  let generated = randomBytes(16).toString('hex')

  while (getApiKeyByKey(generated)) {
    generated = randomBytes(16).toString('hex')
  }

  insertApiKeyStmt.run(generated, normalizedEmail, 'free', now, today)

  return { apiKey: generated, tier: 'free' }
}

function getRateLimit(ip: string, apiKey: string | null): {
  allowed: boolean
  limit: number
  resetAt: string
  apiKey: string | null
} {
  const today = utcDateKey()
  const resetAt = utcMidnightReset()

  if (apiKey) {
    const row = getApiKeyByKey(apiKey)
    if (row) {
      if (row.last_reset !== today) {
        updateApiKeyResetStmt.run(today, apiKey)
        row.checks_today = 0
        row.last_reset = today
      }

      const tier = row.tier === 'pro' ? 'pro' : 'free'
      const limit = tier === 'pro' ? 1000 : 100

      if (tier === 'free' && row.checks_today >= limit) {
        return {
          allowed: false,
          limit,
          resetAt,
          apiKey,
        }
      }

      updateApiKeyChecksStmt.run(apiKey)

      return {
        allowed: true,
        limit,
        resetAt,
        apiKey,
      }
    }
  }

  let row = findRateLimitByIpStmt.get(ip) as RateLimitRow | null
  if (!row) {
    insertRateLimitStmt.run(ip, today)
    row = {
      ip,
      checks_today: 0,
      last_reset: today,
    }
  }

  if (row.last_reset !== today) {
    updateRateLimitResetStmt.run(today, ip)
    row.checks_today = 0
    row.last_reset = today
  }

  if (row.checks_today >= 10) {
    return {
      allowed: false,
      limit: 10,
      resetAt,
      apiKey: null,
    }
  }

  updateRateLimitChecksStmt.run(ip)

  return {
    allowed: true,
    limit: 10,
    resetAt,
    apiKey: null,
  }
}

function getHistoryForApiKey(apiKey: string) {
  return (getHistoryStmt.all(apiKey) as Array<{
    id: number
    api_key: string
    ip: string
    url: string
    status_code: number
    response_time_ms: number
    created_at: string
  }>)
}

function isValidEmail(email: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
}

function recordCheck(apiKey: string | null, ip: string, payload: CheckPayload): void {
  insertCheckStmt.run(
    apiKey,
    ip,
    payload.url,
    payload.statusCode,
    payload.responseTimeMs,
    payload.timestamp,
  )
}

function landingHtml(): string {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Pulse — Site Intelligence API</title>
  <style>
    :root {
      --bg: #090b10;
      --panel: #11141d;
      --panel-soft: #171a24;
      --text: #f7f9ff;
      --muted: #9aa4bf;
      --accent: #39c5ff;
      --accent-strong: #7ce0ff;
      --border: #2a3040;
      --good: #3ddc97;
      --bad: #ff6378;
      --shadow: 0 24px 90px rgba(6, 12, 28, 0.5);
      font-synthesis-weight: none;
    }

    * {
      box-sizing: border-box;
    }

    body {
      margin: 0;
      font-family: 'Inter', 'Segoe UI', Roboto, system-ui, sans-serif;
      min-height: 100vh;
      color: var(--text);
      background: radial-gradient(circle at 8% 8%, #17203a 0%, transparent 32%),
        radial-gradient(circle at 92% 88%, #16182a 0%, transparent 32%),
        linear-gradient(150deg, #02040a 0%, var(--bg) 50%, #0b0f1a 100%);
      display: grid;
      place-items: center;
      padding: 2rem;
    }

    .wrap {
      width: min(980px, 100%);
      background: linear-gradient(180deg, rgba(17, 20, 29, 0.9), rgba(12, 16, 23, 0.95));
      border: 1px solid var(--border);
      border-radius: 20px;
      box-shadow: var(--shadow);
      padding: clamp(1.1rem, 3vw, 2.2rem);
      backdrop-filter: blur(4px);
    }

    header {
      margin-bottom: 1.5rem;
    }

    h1 {
      margin: 0;
      font-size: clamp(1.6rem, 2vw + 1rem, 2.4rem);
      letter-spacing: 0.2px;
      display: inline-flex;
      align-items: center;
      gap: 0.45rem;
    }

    h1::before {
      content: '';
      width: 0.7rem;
      height: 0.7rem;
      border-radius: 999px;
      background: var(--accent);
      box-shadow: 0 0 16px var(--accent);
      display: inline-block;
    }

    .subtitle {
      color: var(--muted);
      margin: 0.7rem 0 0;
      max-width: 60ch;
      line-height: 1.5;
    }

    form {
      margin-top: 1.3rem;
      display: grid;
      grid-template-columns: 1fr auto;
      gap: 0.75rem;
    }

    input {
      width: 100%;
      border-radius: 10px;
      border: 1px solid var(--border);
      background: var(--panel);
      color: var(--text);
      padding: 0.86rem 1rem;
      font-size: 1rem;
      outline: none;
    }

    input:focus {
      border-color: var(--accent);
      box-shadow: 0 0 0 3px rgba(57, 197, 255, 0.17);
    }

    button {
      border: 0;
      border-radius: 10px;
      padding: 0.82rem 1.1rem;
      font-weight: 600;
      background: linear-gradient(120deg, var(--accent), var(--accent-strong));
      color: #071120;
      cursor: pointer;
    }

    button:hover {
      filter: brightness(1.05);
    }

    .result {
      margin-top: 1.1rem;
      border: 1px solid var(--border);
      background: var(--panel-soft);
      border-radius: 12px;
      padding: 1rem;
      min-height: 120px;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', monospace;
      font-size: 0.9rem;
      line-height: 1.45;
    }

    .section {
      margin-top: 1.4rem;
      border: 1px solid var(--border);
      border-radius: 14px;
      background: rgba(20, 24, 35, 0.75);
      padding: 1rem;
    }

    .section h2 {
      margin: 0;
      font-size: 1.05rem;
      color: #d6e4ff;
    }

    .section p {
      color: var(--muted);
      margin: 0.35rem 0 0.8rem;
      line-height: 1.5;
    }

    .section pre {
      margin: 0;
      overflow-x: auto;
      border-radius: 10px;
      background: #050913;
      color: #d1dcff;
      padding: 0.75rem;
      border: 1px solid var(--border);
      font-size: 0.85rem;
      line-height: 1.45;
      white-space: pre-wrap;
    }

    .api-key-result {
      margin-top: 0.7rem;
      color: var(--good);
      min-height: 1.3rem;
      word-break: break-all;
      font-size: 0.9rem;
    }

    .grid {
      margin-top: 1.4rem;
      display: grid;
      gap: 1rem;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    }

    .card {
      border: 1px solid var(--border);
      border-radius: 14px;
      background: rgba(20, 24, 35, 0.75);
      padding: 0.95rem;
    }

    .card h2 {
      margin: 0;
      font-size: 1rem;
      color: #d6e4ff;
    }

    .card p {
      margin: 0.45rem 0 0;
      color: var(--muted);
      line-height: 1.5;
    }

    .price {
      font-weight: 700;
      color: var(--text);
      margin-top: 0.5rem;
      font-size: 1.25rem;
    }

    .good {
      color: var(--good);
    }

    .bad {
      color: var(--bad);
    }

    footer {
      margin-top: 1.4rem;
      color: var(--muted);
      font-size: 0.92rem;
      text-align: right;
    }

    @media (max-width: 640px) {
      .wrap {
        padding: 1rem;
      }

      form {
        grid-template-columns: 1fr;
      }
    }
  </style>
</head>
<body>
  <main class="wrap">
    <header>
      <h1>Pulse — Site Intelligence API</h1>
      <p class="subtitle">Instant website health checks — response time, SSL, headers, redirects</p>
    </header>

    <form id="check-form">
      <input id="url-input" name="url" type="url" placeholder="https://example.com" required />
      <button type="submit">Analyze</button>
    </form>

    <div id="result" class="result">Run an analysis to view JSON diagnostics.</div>

    <section class="section">
      <h2>API Documentation</h2>
      <p>Try these requests directly from the command line.</p>
      <p><strong>Check endpoint:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/check?url=https://example.com'</pre>
      <p><strong>Register:</strong></p>
      <pre>curl -s -X POST 'http://147.93.131.124/api/register' \
  -H 'Content-Type: application/json' \
  -d '{"email":"you@example.com"}'</pre>
      <p><strong>History:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/history' \
  -H 'X-API-Key: YOUR_API_KEY'</pre>
      <p><strong>Account:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/account' \
  -H 'X-API-Key: YOUR_KEY'</pre>
      <p><strong>Subscribe:</strong></p>
      <pre>curl -s -X POST 'http://147.93.131.124/api/subscribe' \
  -H 'Content-Type: application/json' \
  -d '{"email":"you@example.com"}'</pre>
      <p><strong>Monitors:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/monitors' \
  -H 'X-API-Key: YOUR_KEY'</pre>
      <p><strong>Create Monitor:</strong></p>
      <pre>curl -s -X POST 'http://147.93.131.124/api/monitors' \
  -H 'X-API-Key: YOUR_KEY' \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://example.com","interval_minutes":5}'</pre>
    </section>

    <section class="section">
      <h2>Registration</h2>
      <form id="register-form" style="grid-template-columns: 1fr auto;">
        <input id="register-email" type="email" placeholder="you@example.com" required />
        <button type="submit">Get API Key</button>
      </form>
      <div id="register-result" class="api-key-result"></div>
    </section>

    <section class="section">
      <h2>Pricing</h2>
      <div class="grid">
        <article class="card">
          <h2>Free</h2>
          <p>10 checks/day anonymous</p>
          <p>100 checks/day with API key</p>
        </article>
        <article class="card">
          <h2>Pro</h2>
          <p class="price">$9/month</p>
          <p>1000 checks/day</p>
          <p>scheduled URL monitoring</p>
          <p>webhook alerts</p>
        </article>
      </div>
      <form id="subscribe-form" style="grid-template-columns: 1fr auto; margin-top: 0.8rem;">
        <input id="subscribe-email" type="email" placeholder="you@example.com" required />
        <button type="submit">Subscribe to Pro</button>
      </form>
      <div id="subscribe-result" class="api-key-result"></div>
    </section>

    <footer>Powered by Opus</footer>
  </main>

  <script>
    const checkForm = document.getElementById('check-form')
    const urlInput = document.getElementById('url-input')
    const result = document.getElementById('result')
    const registerForm = document.getElementById('register-form')
    const registerEmail = document.getElementById('register-email')
    const registerResult = document.getElementById('register-result')
    const subscribeForm = document.getElementById('subscribe-form')
    const subscribeEmail = document.getElementById('subscribe-email')
    const subscribeResult = document.getElementById('subscribe-result')

    checkForm.addEventListener('submit', async function (event) {
      event.preventDefault()
      const url = urlInput.value.trim()
      if (!url) {
        result.textContent = 'Please provide a valid URL.'
        return
      }

      result.textContent = 'Analyzing...'

      try {
        const response = await fetch('/api/check?url=' + encodeURIComponent(url))
        const data = await response.json()
        result.textContent = JSON.stringify(data, null, 2)
      } catch (error) {
        const message = error && error.message ? error.message : 'Unknown error'
        result.textContent = 'Request failed: ' + message
      }
    })

    registerForm.addEventListener('submit', async function (event) {
      event.preventDefault()
      const email = registerEmail.value.trim()
      if (!email) {
        registerResult.textContent = 'Please provide an email address.'
        return
      }

      registerResult.textContent = 'Requesting key...'

      try {
        const response = await fetch('/api/register', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ email: email }),
        })

        const body = await response.json()
        if (response.ok && body.apiKey) {
          registerResult.textContent = 'Your API key: ' + body.apiKey
        } else if (body.error) {
          registerResult.textContent = body.error
        } else {
          registerResult.textContent = 'Could not get API key.'
        }
      } catch (error) {
        const message = error && error.message ? error.message : 'Unknown error'
        registerResult.textContent = 'Request failed: ' + message
      }
    })

    subscribeForm.addEventListener('submit', async function (event) {
      event.preventDefault()
      const email = subscribeEmail.value.trim()
      if (!email) {
        subscribeResult.textContent = 'Please provide an email address.'
        return
      }

      subscribeResult.textContent = 'Starting checkout flow...'

      try {
        const response = await fetch('/api/subscribe', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ email: email }),
        })

        const body = await response.json()
        if (response.ok && body.checkoutUrl) {
          subscribeResult.textContent = 'Checkout URL: ' + body.checkoutUrl
        } else if (body.error) {
          subscribeResult.textContent = body.error
        } else if (body.message) {
          subscribeResult.textContent = body.message
        } else {
          subscribeResult.textContent = 'Could not start checkout.'
        }
      } catch (error) {
        const message = error && error.message ? error.message : 'Unknown error'
        subscribeResult.textContent = 'Request failed: ' + message
      }
    })
  </script>
</body>
</html>`
}

const server = Bun.serve({
  port: PORT,
  hostname: '0.0.0.0',
  async fetch(request) {
    const url = new URL(request.url)
    const path = url.pathname

    if (request.method === 'OPTIONS') {
      return withCors(null, { status: 204 })
    }

    if (path === '/') {
      if (request.method !== 'GET') {
        return withCors('Method Not Allowed', { status: 405 })
      }

      return withCors(landingHtml(), {
        status: 200,
        headers: {
          'Content-Type': 'text/html; charset=utf-8',
        },
      })
    }

    if (path === '/api/health') {
      if (request.method !== 'GET') {
        return withCors(JSON.stringify({ error: 'Method Not Allowed' }), { status: 405 })
      }

      return withCors(
        JSON.stringify({
          status: 'ok',
          uptime: process.uptime(),
        }),
        {
          headers: {
            'Content-Type': 'application/json',
          },
        },
      )
    }

    if (path === '/api/register') {
      if (request.method !== 'POST') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const payload = await request.json().catch(() => null)
      const email =
        payload && typeof payload.email === 'string' ? payload.email.trim() : ''

      if (!email || !isValidEmail(email)) {
        return withJson({ error: 'Invalid email format' }, { status: 400 })
      }

      const result = getOrCreateApiKey(email)
      const limit = result.tier === 'pro' ? 1000 : 100

      return withJson(
        {
          apiKey: result.apiKey,
          tier: result.tier,
          limit,
        },
        {
          status: 200,
        },
      )
    }

    if (path === '/api/subscribe') {
      if (request.method !== 'POST') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const payload = await request.json().catch(() => null)
      const email =
        payload && typeof payload.email === 'string' ? payload.email.trim().toLowerCase() : ''
      if (!email || !isValidEmail(email)) {
        return withJson({ error: 'Invalid email format' }, { status: 400 })
      }

      const row = getApiKeyByEmail(email)
      if (!row) {
        return withJson({ error: 'Email not registered' }, { status: 404 })
      }

      if (!stripe) {
        return withJson(
          {
            error: 'Stripe not configured',
            message: 'Payment processing is not yet available',
          },
          { status: 503 },
        )
      }

      try {
        const session = await stripe.checkout.sessions.create({
          mode: 'subscription',
          line_items: [
            {
              price: STRIPE_PRICE_ID,
              quantity: 1,
            },
          ],
          customer_email: row.email,
          success_url: 'http://147.93.131.124/?upgraded=true',
          cancel_url: 'http://147.93.131.124/?cancelled=true',
        })

        return withJson({ checkoutUrl: session.url }, { status: 200 })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Stripe error'
        return withJson({ error: message }, { status: 502 })
      }
    }

    if (path === '/api/webhooks/stripe') {
      if (request.method !== 'POST') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      if (!stripe || !STRIPE_WEBHOOK_SECRET) {
        return withJson({ error: 'Webhook not configured' }, { status: 503 })
      }

      const sig = request.headers.get('stripe-signature')
      const body = await request.text()
      try {
        const event = stripe.webhooks.constructEvent(body, sig || '', STRIPE_WEBHOOK_SECRET)

        if (event.type === 'checkout.session.completed') {
          const checkoutSession = event.data.object as {
            customer_email?: string | null
          }

          const customerEmail = checkoutSession.customer_email?.trim().toLowerCase()
          if (customerEmail) {
            updateApiKeyTierStmt.run('pro', customerEmail)
          }
        }

        if (event.type === 'customer.subscription.deleted') {
          const subscription = event.data.object as {
            customer_email?: string | null
          }

          const customerEmail = subscription.customer_email?.trim().toLowerCase()
          if (customerEmail) {
            updateApiKeyTierStmt.run('free', customerEmail)
          }
        }

        return withJson({ received: true }, { status: 200 })
      } catch {
        return withJson({ error: 'Invalid signature' }, { status: 400 })
      }
    }

    if (path === '/api/account') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      if (!apiKey) {
        return withJson({ error: 'Missing X-API-Key header' }, { status: 401 })
      }

      const row = getApiKeyByKey(apiKey)
      if (!row) {
        return withJson({ error: 'Invalid API key' }, { status: 401 })
      }

      const today = utcDateKey()
      if (row.last_reset !== today) {
        updateApiKeyResetStmt.run(today, apiKey)
        row.checks_today = 0
        row.last_reset = today
      }

      return withJson({
        email: row.email,
        tier: row.tier,
        checksToday: row.checks_today,
        limitPerDay: row.tier === 'pro' ? 1000 : 100,
      })
    }

    if (path === '/api/check') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson(
          { error: 'Missing required ?url= query parameter' },
          { status: 400 },
        )
      }

      try {
        new URL(normalizeUrl(target))
      } catch {
        return withJson(
          { error: 'Invalid URL format' },
          { status: 400 },
        )
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rateLimit = getRateLimit(clientIp, apiKey)

      if (!rateLimit.allowed) {
        const headers = new Headers()
        headers.set('Content-Type', 'application/json')
        headers.set('Retry-After', String(secondsUntilMidnightUtc()))

        return withCors(
          JSON.stringify({
            error: 'Rate limit exceeded',
            limit: rateLimit.limit,
            resetAt: rateLimit.resetAt,
          }),
          {
            status: 429,
            headers,
          },
        )
      }

      const payload = await checkUrl(target)
      recordCheck(rateLimit.apiKey, clientIp, payload)

      return withJson(payload)
    }

    if (path.startsWith('/api/monitors')) {
      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      if (!apiKey) {
        return withJson({ error: 'Missing X-API-Key header' }, { status: 401 })
      }

      const apiKeyRow = getApiKeyByKey(apiKey)
      if (!apiKeyRow) {
        return withJson({ error: 'Invalid API key' }, { status: 401 })
      }

      if (path === '/api/monitors') {
        if (request.method === 'GET') {
          const monitors = getMonitorsStmt.all(apiKeyRow.key) as MonitorRow[]
          return withJson(monitors)
        }

        if (request.method === 'POST') {
          if (apiKeyRow.tier !== 'pro') {
            return withJson({ error: 'Pro tier required' }, { status: 403 })
          }

          const payload = await request.json().catch(() => null)
          const monitorUrl = payload && typeof payload.url === 'string' ? payload.url.trim() : ''
          if (!monitorUrl) {
            return withJson({ error: 'Missing url' }, { status: 400 })
          }

          const requestedInterval =
            payload && typeof payload.interval_minutes === 'number' && Number.isFinite(payload.interval_minutes)
              ? Math.floor(payload.interval_minutes)
              : 5
          const intervalMinutes = Math.max(1, Math.min(60, requestedInterval))
          const now = toISOStringNow()
          const inserted = insertMonitorStmt.run(apiKeyRow.key, monitorUrl, intervalMinutes, now) as {
            lastInsertRowid: number
          }

          return withJson(
            {
              id: inserted.lastInsertRowid,
              url: monitorUrl,
              interval_minutes: intervalMinutes,
              status: 'active',
            },
            { status: 201 },
          )
        }

        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const deleteMatch = path.match(/^\/api\/monitors\/(\d+)$/)
      if (deleteMatch) {
        if (request.method !== 'DELETE') {
          return withJson({ error: 'Method Not Allowed' }, { status: 405 })
        }

        const monitorId = Number(deleteMatch[1])
        deleteMonitorStmt.run(monitorId, apiKeyRow.key)
        return withJson({ deleted: true })
      }

      return withCors('Not Found', { status: 404 })
    }

    if (path === '/api/history') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      if (!apiKey) {
        return withJson({ error: 'Missing X-API-Key header' }, { status: 401 })
      }

      const row = getApiKeyByKey(apiKey)
      if (!row) {
        return withJson({ error: 'Invalid API key' }, { status: 401 })
      }

      const history = getHistoryForApiKey(row.key)
      return withJson(history)
    }

    return withCors('Not Found', { status: 404 })
  },
})

setInterval(async () => {
  const monitors = getDueMonitorsStmt.all() as any[]
  const now = new Date()

  for (const mon of monitors) {
    const lastCheck = mon.last_check ? new Date(mon.last_check) : new Date(0)
    const diffMinutes = (now.getTime() - lastCheck.getTime()) / 60000

    if (diffMinutes >= mon.interval_minutes) {
      try {
        const result = await checkUrl(mon.url)
        insertCheckStmt.run(
          mon.api_key,
          '127.0.0.1',
          result.url,
          result.statusCode,
          result.responseTimeMs,
          result.timestamp,
        )
        db.prepare('UPDATE monitors SET last_check = ? WHERE id = ?').run(result.timestamp, mon.id)
      } catch {}
    }
  }
}, 60000)

console.log(`Pulse — Site Intelligence API running on http://localhost:${PORT}`)
console.log(`Port open in server: ${server.port}`)
