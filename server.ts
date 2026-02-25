import tls from 'node:tls'
import { randomBytes } from 'node:crypto'
import { resolve as dnsResolve } from 'node:dns/promises'
import { appendFileSync } from 'node:fs'
import { Database } from 'bun:sqlite'
import Stripe from 'stripe'
import nodemailer from 'nodemailer'

const PORT = 3000
const MAX_REDIRECTS = 5
const DB_PATH = '/root/opus-orchestrator/workspace/opus-api/pulse.db'
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || ''
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || ''
const STRIPE_PRICE_ID = process.env.STRIPE_PRICE_ID || ''
const stripe = STRIPE_SECRET_KEY ? new Stripe(STRIPE_SECRET_KEY) : null

const SMTP_HOST = process.env.SMTP_HOST || ''
const SMTP_PORT = parseInt(process.env.SMTP_PORT || '587', 10)
const SMTP_USER = process.env.SMTP_USER || ''
const SMTP_PASS = process.env.SMTP_PASS || ''
const SMTP_FROM = process.env.SMTP_FROM || ''
const smtpConfigured = !!(SMTP_HOST && SMTP_USER && SMTP_PASS)

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
  alert_url: string | null
  last_status_code: number | null
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
    created_at TEXT,
    alert_url TEXT,
    last_status_code INTEGER
  );

  CREATE TABLE IF NOT EXISTS endpoint_rate_limits (
    key TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    checks_today INTEGER DEFAULT 0,
    last_reset TEXT,
    PRIMARY KEY (key, endpoint)
  );
`)

try { db.exec('ALTER TABLE monitors ADD COLUMN alert_url TEXT') } catch {}
try { db.exec('ALTER TABLE monitors ADD COLUMN last_status_code INTEGER') } catch {}

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
  `INSERT INTO monitors (api_key, url, interval_minutes, last_check, status, created_at, alert_url)
   VALUES (?, ?, ?, NULL, 'active', ?, ?)`
)
const getMonitorsStmt = db.prepare<MonitorRow, [string]>(
  "SELECT id, api_key, url, interval_minutes, last_check, status, created_at, alert_url, last_status_code FROM monitors WHERE api_key = ? AND status = 'active'",
)
const deleteMonitorStmt = db.prepare(
  'UPDATE monitors SET status = \'deleted\' WHERE id = ? AND api_key = ?',
)
const getDueMonitorsStmt = db.prepare<
  Pick<MonitorRow, 'id' | 'api_key' | 'url' | 'interval_minutes' | 'last_check' | 'alert_url' | 'last_status_code'>,
  []
>("SELECT id, api_key, url, interval_minutes, last_check, alert_url, last_status_code FROM monitors WHERE status = 'active'")
const updateMonitorStatusCodeStmt = db.prepare('UPDATE monitors SET last_status_code = ? WHERE id = ?')
const getMonitorByIdAndKeyStmt = db.prepare<MonitorRow, [number, string]>('SELECT * FROM monitors WHERE id = ? AND api_key = ?')
const getChecksByKeyAndUrlStmt = db.prepare('SELECT id, api_key, ip, url, status_code, response_time_ms, created_at FROM checks WHERE api_key = ? AND url = ? ORDER BY id DESC LIMIT 100')

const findEndpointRateLimitStmt = db.prepare<{ key: string; endpoint: string; checks_today: number; last_reset: string }, [string, string]>('SELECT * FROM endpoint_rate_limits WHERE key = ? AND endpoint = ?')
const upsertEndpointRateLimitStmt = db.prepare('INSERT INTO endpoint_rate_limits (key, endpoint, checks_today, last_reset) VALUES (?, ?, 1, ?) ON CONFLICT(key, endpoint) DO UPDATE SET checks_today = checks_today + 1')
const resetEndpointRateLimitStmt = db.prepare('UPDATE endpoint_rate_limits SET checks_today = 1, last_reset = ? WHERE key = ? AND endpoint = ?')

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
  if (!headers.has('Cache-Control')) {
    headers.set('Cache-Control', 'no-cache')
  }

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

function getEndpointRateLimit(
  ip: string,
  apiKey: string | null,
  endpoint: string,
): { allowed: boolean; limit: number; resetAt: string } {
  const today = utcDateKey()
  const resetAt = utcMidnightReset()
  const key = apiKey || ('ip:' + ip)

  let tier = 'anon'
  if (apiKey) {
    const row = getApiKeyByKey(apiKey)
    if (row) tier = row.tier === 'pro' ? 'pro' : 'free'
  }

  const limits: Record<string, number> = { anon: 5, free: 50, pro: 500 }
  const limit = limits[tier] || 5

  const row = findEndpointRateLimitStmt.get(key, endpoint) as { key: string; endpoint: string; checks_today: number; last_reset: string } | null
  if (row && row.last_reset === today) {
    if (row.checks_today >= limit) {
      return { allowed: false, limit, resetAt }
    }
    upsertEndpointRateLimitStmt.run(key, endpoint, today)
    return { allowed: true, limit, resetAt }
  }

  if (row) {
    resetEndpointRateLimitStmt.run(today, key, endpoint)
  } else {
    upsertEndpointRateLimitStmt.run(key, endpoint, today)
  }
  return { allowed: true, limit, resetAt }
}

async function sendAlertEmail(to: string, subject: string, body: string): Promise<boolean> {
  if (!smtpConfigured) {
    console.log('[email] SMTP not configured, skipping alert to ' + to)
    return false
  }
  try {
    const transporter = nodemailer.createTransport({
      host: SMTP_HOST,
      port: SMTP_PORT,
      secure: SMTP_PORT === 465,
      auth: { user: SMTP_USER, pass: SMTP_PASS },
    })
    await transporter.sendMail({ from: SMTP_FROM, to, subject, text: body })
    console.log('[email] Alert sent to ' + to)
    return true
  } catch (err) {
    console.log('[email] Failed to send to ' + to + ': ' + (err instanceof Error ? err.message : 'unknown'))
    return false
  }
}

function dashboardHtml(): string {
  return '<!doctype html>\n<html lang="en">\n<head>\n<meta charset="UTF-8"/>\n<meta name="viewport" content="width=device-width,initial-scale=1.0"/>\n<title>Pulse Dashboard</title>\n<style>\n:root{--bg:#090b10;--panel:#11141d;--text:#f7f9ff;--muted:#9aa4bf;--accent:#39c5ff;--border:#2a3040;--good:#3ddc97;--bad:#ff6378}\n*{box-sizing:border-box}\nbody{margin:0;font-family:Inter,system-ui,sans-serif;background:var(--bg);color:var(--text);padding:2rem}\n.wrap{max-width:960px;margin:0 auto}\nh1{color:var(--accent);margin:0 0 .5rem}\n.info{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:1rem;margin-bottom:1rem}\n.info span{color:var(--muted);margin-right:1.5rem}\n.info strong{color:var(--text)}\ntable{width:100%;border-collapse:collapse;margin-top:.5rem}\nth,td{text-align:left;padding:.5rem .7rem;border-bottom:1px solid var(--border)}\nth{color:var(--muted);font-size:.85rem;text-transform:uppercase}\ntd{font-size:.9rem}\n.good{color:var(--good)}.bad{color:var(--bad)}\nform.create{display:grid;grid-template-columns:2fr 1fr 2fr auto;gap:.5rem;margin:1rem 0}\ninput,button{border-radius:8px;padding:.6rem .8rem;font-size:.9rem;border:1px solid var(--border);background:var(--panel);color:var(--text)}\nbutton{background:linear-gradient(120deg,var(--accent),#7ce0ff);color:#071120;border:0;cursor:pointer;font-weight:600}\nbutton:hover{filter:brightness(1.05)}\n.section{margin-top:1.5rem}\n.section h2{margin:0 0 .5rem;font-size:1.1rem}\n.msg{color:var(--muted);padding:1rem;text-align:center}\na{color:var(--accent);text-decoration:none}\na:hover{text-decoration:underline}\n.del{background:var(--bad);color:#fff;padding:.3rem .6rem;border-radius:6px;font-size:.8rem;cursor:pointer;border:0}\n.nav{display:flex;gap:1rem;margin-bottom:1rem}\n#key-input{display:flex;gap:.5rem;margin-bottom:1.5rem}\n#key-input input{flex:1}\n</style>\n</head>\n<body>\n<div class="wrap">\n<div class="nav"><a href="/">&larr; Home</a><h1>Pulse Dashboard</h1></div>\n<div id="key-input"><input id="api-key" type="text" placeholder="Enter your API key"/><button onclick="loadDashboard()">Load</button></div>\n<div id="account" class="info" style="display:none"></div>\n<div class="section"><h2>Monitors</h2>\n<form class="create" id="monitor-form" style="display:none">\n<input id="mon-url" placeholder="https://example.com" required/>\n<input id="mon-interval" type="number" value="5" min="1" max="60" placeholder="min"/>\n<input id="mon-alert" placeholder="alert webhook URL (optional)"/>\n<button type="submit">Create Monitor</button>\n</form>\n<div id="monitors"><p class="msg">Enter your API key above.</p></div>\n</div>\n<div class="section"><h2>Recent Checks</h2>\n<div id="checks"><p class="msg">Enter your API key above.</p></div>\n</div>\n</div>\n<script>\nvar KEY=""\nfunction getKey(){KEY=document.getElementById("api-key").value.trim();return KEY}\nfunction loadDashboard(){if(!getKey())return;loadAccount();loadMonitors();loadChecks()}\nfunction loadAccount(){\nfetch("/api/account",{headers:{"X-API-Key":KEY}}).then(function(r){return r.json()}).then(function(d){\nvar el=document.getElementById("account");el.style.display="block";\nel.innerHTML="<span>Email: <strong>"+d.email+"</strong></span><span>Tier: <strong>"+d.tier+"</strong></span><span>Checks today: <strong>"+d.checksToday+"/"+d.limitPerDay+"</strong></span>"\n}).catch(function(){})}\nfunction loadMonitors(){\nfetch("/api/monitors",{headers:{"X-API-Key":KEY}}).then(function(r){return r.json()}).then(function(list){\nvar el=document.getElementById("monitors");\ndocument.getElementById("monitor-form").style.display="grid";\nif(!list.length){el.innerHTML="<p class=\\"msg\\">No monitors yet.</p>";return}\nvar h="<table><tr><th>ID</th><th>URL</th><th>Interval</th><th>Status</th><th>Alert URL</th><th></th></tr>";\nfor(var i=0;i<list.length;i++){var m=list[i];var cls=m.last_status_code===200?"good":"bad";\nh+="<tr><td>"+m.id+"</td><td>"+m.url+"</td><td>"+m.interval_minutes+"m</td><td class=\\""+cls+"\\">"+((m.last_status_code)||"pending")+"</td><td>"+(m.alert_url||"none")+"</td><td><button class=\\"del\\" onclick=\\"delMon("+m.id+")\\">Delete</button></td></tr>"}\nh+="</table>";el.innerHTML=h\n}).catch(function(){})}\nfunction loadChecks(){\nfetch("/api/history",{headers:{"X-API-Key":KEY}}).then(function(r){return r.json()}).then(function(list){\nvar el=document.getElementById("checks");\nif(!list.length){el.innerHTML="<p class=\\"msg\\">No checks yet.</p>";return}\nvar h="<table><tr><th>URL</th><th>Status</th><th>Time</th><th>Date</th></tr>";\nfor(var i=0;i<list.length;i++){var c=list[i];var cls=c.status_code===200?"good":"bad";\nh+="<tr><td>"+c.url+"</td><td class=\\""+cls+"\\">"+c.status_code+"</td><td>"+c.response_time_ms+"ms</td><td>"+c.created_at+"</td></tr>"}\nh+="</table>";el.innerHTML=h\n}).catch(function(){})}\nfunction delMon(id){\nfetch("/api/monitors/"+id,{method:"DELETE",headers:{"X-API-Key":KEY}}).then(function(){loadMonitors()}).catch(function(){})}\ndocument.getElementById("monitor-form").addEventListener("submit",function(e){\ne.preventDefault();\nvar u=document.getElementById("mon-url").value.trim();\nvar iv=parseInt(document.getElementById("mon-interval").value)||5;\nvar al=document.getElementById("mon-alert").value.trim()||null;\nfetch("/api/monitors",{method:"POST",headers:{"X-API-Key":KEY,"Content-Type":"application/json"},body:JSON.stringify({url:u,interval_minutes:iv,alert_url:al})}).then(function(r){return r.json()}).then(function(){loadMonitors();document.getElementById("mon-url").value=""}).catch(function(){})})\nvar stored=localStorage.getItem("pulse_api_key");\nif(stored){document.getElementById("api-key").value=stored;loadDashboard()}\nfunction getKey(){KEY=document.getElementById("api-key").value.trim();localStorage.setItem("pulse_api_key",KEY);return KEY}\n</script>\n</body>\n</html>'
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
      <p class="subtitle">Instant website health checks — response time, SSL, headers, redirects, DNS, performance scoring</p>
      <div style="margin-top:0.8rem"><a href="/dashboard" style="color:var(--accent);font-weight:600;text-decoration:none;border:1px solid var(--accent);border-radius:8px;padding:0.5rem 1rem;display:inline-block">Dashboard &rarr;</a> <a href="/status" style="color:var(--accent);font-weight:600;text-decoration:none;border:1px solid var(--accent);border-radius:8px;padding:0.5rem 1rem;display:inline-block;margin-left:0.5rem">Status &rarr;</a> <a href="/docs" style="color:var(--accent);font-weight:600;text-decoration:none;border:1px solid var(--accent);border-radius:8px;padding:0.5rem 1rem;display:inline-block;margin-left:0.5rem">API Docs &rarr;</a></div>
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
  -d '{"url":"https://example.com","interval_minutes":5,"alert_url":"https://your-webhook.com/alert"}'</pre>
      <p><strong>Monitor Checks:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/monitors/1/checks' \
  -H 'X-API-Key: YOUR_KEY'</pre>
      <p><strong>DNS Analysis:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/dns?domain=example.com'</pre>
      <p><strong>Performance Score:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/perf?url=https://example.com'</pre>
      <p><strong>SEO Audit:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/seo?url=https://example.com'</pre>
      <p><strong>Test Webhook:</strong></p>
      <pre>curl -s -X POST 'http://147.93.131.124/api/test-webhook' \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://httpbin.org/post"}'</pre>
      <p><strong>Batch Analysis:</strong></p>
      <pre>curl -s -X POST 'http://147.93.131.124/api/batch' \
  -H 'Content-Type: application/json' \
  -d '{"urls":["https://example.com","https://google.com"]}'</pre>
      <p><strong>Uptime Badge:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/badge/1'
# Returns SVG image — embed in README:
# ![Uptime](http://147.93.131.124/api/badge/1)</pre>
      <p><strong>Compare URLs:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/compare?urls=https://example.com,https://google.com'</pre>
      <p><strong>Uptime Stats:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/uptime'</pre>
      <p><strong>Security Headers Audit:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/headers?url=https://example.com'</pre>
      <p><strong>Technology Stack Detection:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/tech?url=https://example.com'</pre>
      <p><strong>Site Quality Score:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/score?url=https://example.com'</pre>
      <p><strong>Sitemap Parser:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/sitemap?url=https://example.com/sitemap.xml'</pre>
      <p><strong>SSL Certificate Monitor:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/ssl?url=https://example.com'</pre>
      <p><strong>Robots.txt Parser:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/robots?url=https://example.com'</pre>
      <p><strong>Mixed Content Scanner:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/mixed-content?url=https://example.com'</pre>
      <p><strong>Response Header Timeline:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/timeline?url=https://example.com'</pre>
      <p><strong>Accessibility Audit:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/accessibility?url=https://example.com'</pre>
      <p><strong>Cookie Scanner:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/cookies?url=https://example.com'</pre>
      <p><strong>Page Weight Analyzer:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/weight?url=https://example.com'</pre>
      <p><strong>Carbon Footprint Estimator:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/carbon?url=https://example.com'</pre>
      <p><strong>Link Checker:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/links?url=https://example.com'</pre>
      <p><strong>Meta Tag Validator:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/meta?url=https://example.com'</pre>
      <p><strong>HTTP/2 Checker:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/http2?url=https://example.com'</pre>
      <p><strong>Structured Data Validator:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/structured-data?url=https://example.com'</pre>
      <p><strong>DNS Blacklist Lookup:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/dnsbl?url=https://example.com'</pre>
      <p><strong>Full API Docs:</strong> <a href="/docs" style="color:var(--accent)">/docs</a></p>
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

    if (path === '/status') {
      if (request.method !== 'GET') {
        return withCors('Method Not Allowed', { status: 405 })
      }

      const uptime = process.uptime()
      const uptimeH = Math.floor(uptime / 3600)
      const uptimeM = Math.floor((uptime % 3600) / 60)
      const uptimeS = Math.floor(uptime % 60)
      const uptimeStr = uptimeH + 'h ' + uptimeM + 'm ' + uptimeS + 's'

      const userCount = (db.prepare('SELECT COUNT(*) as c FROM api_keys').get() as any)?.c || 0
      const checkCount = (db.prepare('SELECT COUNT(*) as c FROM checks').get() as any)?.c || 0
      const monitorCount = (db.prepare("SELECT COUNT(*) as c FROM monitors WHERE status='active'").get() as any)?.c || 0

      const recentChecks = db.prepare('SELECT url, status_code, response_time_ms, created_at FROM checks ORDER BY id DESC LIMIT 10').all() as any[]
      let checksHtml = ''
      for (const c of recentChecks) {
        const cls = c.status_code === 200 ? 'good' : 'bad'
        checksHtml += '<tr><td>' + c.url + '</td><td class="' + cls + '">' + c.status_code + '</td><td>' + c.response_time_ms + 'ms</td><td>' + c.created_at + '</td></tr>'
      }

      const statusPage = '<!doctype html><html lang="en"><head><meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1.0"/><meta http-equiv="refresh" content="30"/><title>Pulse Status</title><style>:root{--bg:#090b10;--panel:#11141d;--text:#f7f9ff;--muted:#9aa4bf;--accent:#39c5ff;--border:#2a3040;--good:#3ddc97;--bad:#ff6378}*{box-sizing:border-box}body{margin:0;font-family:Inter,system-ui,sans-serif;background:var(--bg);color:var(--text);padding:2rem}.wrap{max-width:960px;margin:0 auto}h1{color:var(--accent);margin:0 0 .5rem}.stat{display:inline-block;background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:1rem 1.5rem;margin:.5rem .5rem .5rem 0}.stat .val{font-size:1.8rem;font-weight:700;color:var(--accent)}.stat .lbl{color:var(--muted);font-size:.85rem}table{width:100%;border-collapse:collapse;margin-top:1rem}th,td{text-align:left;padding:.5rem .7rem;border-bottom:1px solid var(--border)}th{color:var(--muted);font-size:.85rem;text-transform:uppercase}.good{color:var(--good)}.bad{color:var(--bad)}a{color:var(--accent);text-decoration:none}.note{color:var(--muted);margin-top:1rem;font-size:.85rem}</style></head><body><div class="wrap"><a href="/">&larr; Home</a><h1>Pulse Status</h1><div><div class="stat"><div class="val">' + uptimeStr + '</div><div class="lbl">Uptime</div></div><div class="stat"><div class="val">' + userCount + '</div><div class="lbl">Registered Users</div></div><div class="stat"><div class="val">' + checkCount + '</div><div class="lbl">Total Checks</div></div><div class="stat"><div class="val">' + monitorCount + '</div><div class="lbl">Active Monitors</div></div></div><h2 style="margin-top:1.5rem">Recent Checks</h2><table><tr><th>URL</th><th>Status</th><th>Time</th><th>Date</th></tr>' + checksHtml + '</table><p class="note">Auto-refreshes every 30 seconds.</p></div></body></html>'

      return withCors(statusPage, {
        status: 200,
        headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'public, max-age=60' },
      })
    }

    if (path === '/dashboard') {
      if (request.method !== 'GET') {
        return withCors('Method Not Allowed', { status: 405 })
      }

      return withCors(dashboardHtml(), {
        status: 200,
        headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'public, max-age=60' },
      })
    }

    if (path === '/') {
      if (request.method !== 'GET') {
        return withCors('Method Not Allowed', { status: 405 })
      }

      return withCors(landingHtml(), {
        status: 200,
        headers: {
          'Content-Type': 'text/html; charset=utf-8',
          'Cache-Control': 'public, max-age=60',
        },
      })
    }

    if (path === '/api/health') {
      if (request.method !== 'GET') {
        return withCors(JSON.stringify({ error: 'Method Not Allowed' }), { status: 405 })
      }

      return withJson({
        status: 'ok',
        uptime: process.uptime(),
      })
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

          const alertUrl = payload && typeof payload.alert_url === 'string' ? payload.alert_url.trim() || null : null
          const requestedInterval =
            payload && typeof payload.interval_minutes === 'number' && Number.isFinite(payload.interval_minutes)
              ? Math.floor(payload.interval_minutes)
              : 5
          const intervalMinutes = Math.max(1, Math.min(60, requestedInterval))
          const now = toISOStringNow()
          const inserted = insertMonitorStmt.run(apiKeyRow.key, monitorUrl, intervalMinutes, now, alertUrl) as {
            lastInsertRowid: number
          }

          return withJson(
            {
              id: inserted.lastInsertRowid,
              url: monitorUrl,
              interval_minutes: intervalMinutes,
              alert_url: alertUrl,
              status: 'active',
            },
            { status: 201 },
          )
        }

        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const checksMatch = path.match(/^\/api\/monitors\/(\d+)\/checks$/)
      if (checksMatch) {
        if (request.method !== 'GET') {
          return withJson({ error: 'Method Not Allowed' }, { status: 405 })
        }

        const monitorId = Number(checksMatch[1])
        const monitor = getMonitorByIdAndKeyStmt.get(monitorId, apiKeyRow.key) as MonitorRow | null
        if (!monitor) {
          return withJson({ error: 'Monitor not found' }, { status: 404 })
        }

        const monUrl = monitor.url
        const altUrl = monUrl.endsWith('/') ? monUrl.slice(0, -1) : monUrl + '/'
        const checks = [
          ...getChecksByKeyAndUrlStmt.all(apiKeyRow.key, monUrl) as any[],
          ...getChecksByKeyAndUrlStmt.all(apiKeyRow.key, altUrl) as any[],
        ].sort((a: any, b: any) => b.id - a.id).slice(0, 100)
        return withJson(checks)
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

    if (path === '/api/dns') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const domain = url.searchParams.get('domain')
      if (!domain) {
        return withJson({ error: 'domain parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'dns')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      const result: Record<string, unknown> = { domain }
      try { result.a = await dnsResolve(domain, 'A') } catch { result.a = [] }
      try { result.mx = await dnsResolve(domain, 'MX') } catch { result.mx = [] }
      try { result.txt = await dnsResolve(domain, 'TXT') } catch { result.txt = [] }
      try { result.ns = await dnsResolve(domain, 'NS') } catch { result.ns = [] }
      try { result.cname = await dnsResolve(domain, 'CNAME') } catch { result.cname = [] }

      return withJson(result)
    }

    if (path === '/api/perf') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'perf')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const t0 = performance.now()
        const response = await fetch(normalized)
        const ttfb = performance.now() - t0
        const buf = await response.arrayBuffer()
        const totalMs = performance.now() - t0
        const sizeBytes = buf.byteLength
        const contentType = response.headers.get('content-type') || 'unknown'
        const compressed = !!response.headers.get('content-encoding')

        let score = 100
        if (ttfb > 200) score -= Math.floor((ttfb - 200) / 100)
        if (sizeBytes > 500 * 1024) score -= Math.floor((sizeBytes - 500 * 1024) / (50 * 1024))
        if (!compressed) score -= 10
        score = Math.max(0, Math.min(100, score))

        return withJson({
          url: normalized,
          ttfb_ms: Math.round(ttfb),
          total_ms: Math.round(totalMs),
          size_bytes: sizeBytes,
          content_type: contentType,
          compressed,
          score,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Fetch failed'
        return withJson({ error: message }, { status: 502 })
      }
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

    if (path === '/api/seo') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'seo')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const response = await fetch(normalized)
        const html = await response.text()

        const titleMatch = html.match(/<title>(.*?)<\/title>/i)
        const title = titleMatch ? titleMatch[1].trim() : null

        const descMatch = html.match(/<meta\s+name=["']description["']\s+content=["'](.*?)["']/i)
          || html.match(/<meta\s+content=["'](.*?)["']\s+name=["']description["']/i)
        const description = descMatch ? descMatch[1].trim() : null

        const h1Matches = html.match(/<h1[\s>]/gi)
        const h1Count = h1Matches ? h1Matches.length : 0

        const imgTags = html.match(/<img\s[^>]*>/gi) || []
        let imagesWithoutAlt = 0
        for (const img of imgTags) {
          if (!/\balt\s*=/i.test(img)) imagesWithoutAlt++
        }

        const canonicalMatch = html.match(/<link\s[^>]*rel=["']canonical["'][^>]*href=["'](.*?)["']/i)
          || html.match(/<link\s[^>]*href=["'](.*?)["'][^>]*rel=["']canonical["']/i)
        const hasCanonical = !!canonicalMatch
        const canonicalUrl = canonicalMatch ? canonicalMatch[1] : null

        const robotsMatch = html.match(/<meta\s+name=["']robots["']\s+content=["'](.*?)["']/i)
          || html.match(/<meta\s+content=["'](.*?)["']\s+name=["']robots["']/i)
        const robots = robotsMatch ? robotsMatch[1].trim() : null

        let score = 100
        if (!title) score -= 10
        if (!description) score -= 10
        score -= imagesWithoutAlt * 5
        if (!hasCanonical) score -= 10
        if (robots && /noindex/i.test(robots)) score -= 5
        score = Math.max(0, Math.min(100, score))

        return withJson({
          url: normalized,
          title,
          description,
          h1_count: h1Count,
          images_without_alt: imagesWithoutAlt,
          has_canonical: hasCanonical,
          canonical_url: canonicalUrl,
          robots,
          score,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Fetch failed'
        return withJson({ error: message }, { status: 502 })
      }
    }

    if (path === '/api/test-webhook') {
      if (request.method !== 'POST') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const payload = await request.json().catch(() => null)
      const webhookUrl = payload && typeof payload.url === 'string' ? payload.url.trim() : ''
      if (!webhookUrl) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      try {
        const t0 = performance.now()
        const resp = await fetch(webhookUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            test: true,
            source: 'pulse',
            timestamp: new Date().toISOString(),
          }),
        })
        const elapsed = performance.now() - t0

        return withJson({
          delivered: true,
          status_code: resp.status,
          response_time_ms: Math.round(elapsed),
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Delivery failed'
        return withJson({ delivered: false, error: message }, { status: 502 })
      }
    }

    if (path === '/api/batch') {
      if (request.method !== 'POST') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'batch')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      const payload = await request.json().catch(() => null)
      const urls = payload && Array.isArray(payload.urls) ? payload.urls : null
      if (!urls || urls.length === 0 || urls.length > 10) {
        return withJson({ error: 'urls array required, max 10' }, { status: 400 })
      }

      const results: Array<{ url: string; statusCode: number; responseTimeMs: number; error?: string }> = []
      for (const u of urls) {
        if (typeof u !== 'string') continue
        const r = await checkUrl(u)
        results.push({ url: r.url, statusCode: r.statusCode, responseTimeMs: r.responseTimeMs, ...(r.error ? { error: r.error } : {}) })
      }

      return withJson({ results, total: urls.length, completed: results.length })
    }

    const badgeMatch = path.match(/^\/api\/badge\/(\d+)$/)
    if (badgeMatch) {
      if (request.method !== 'GET') {
        return withCors('Method Not Allowed', { status: 405 })
      }

      const monitorId = Number(badgeMatch[1])
      const monitor = db.prepare('SELECT * FROM monitors WHERE id = ?').get(monitorId) as MonitorRow | null
      if (!monitor) {
        const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="120" height="20"><rect width="120" height="20" rx="3" fill="#555"/><text x="60" y="14" fill="#fff" font-family="sans-serif" font-size="11" text-anchor="middle">not found</text></svg>`
        return withCors(svg, { status: 404, headers: { 'Content-Type': 'image/svg+xml', 'Cache-Control': 'no-cache, max-age=300' } })
      }

      const since = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString()
      const monUrl = monitor.url
      const altUrl = monUrl.endsWith('/') ? monUrl.slice(0, -1) : monUrl + '/'
      const checks = db.prepare('SELECT status_code FROM checks WHERE (url = ? OR url = ?) AND created_at >= ?').all(monUrl, altUrl, since) as Array<{ status_code: number }>

      let uptimePct = 100
      if (checks.length > 0) {
        const okCount = checks.filter(c => c.status_code === 200).length
        uptimePct = Math.round((okCount / checks.length) * 1000) / 10
      }

      let color = '#4c1'
      if (uptimePct < 99) color = '#dfb317'
      if (uptimePct < 95) color = '#e05d44'

      const label = 'uptime'
      const value = uptimePct + '%'
      const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="110" height="20"><linearGradient id="b" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient><clipPath id="a"><rect width="110" height="20" rx="3" fill="#fff"/></clipPath><g clip-path="url(#a)"><rect width="52" height="20" fill="#555"/><rect x="52" width="58" height="20" fill="${color}"/><rect width="110" height="20" fill="url(#b)"/></g><g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11"><text x="26" y="15" fill="#010101" fill-opacity=".3">${label}</text><text x="26" y="14">${label}</text><text x="80" y="15" fill="#010101" fill-opacity=".3">${value}</text><text x="80" y="14">${value}</text></g></svg>`

      return withCors(svg, { status: 200, headers: { 'Content-Type': 'image/svg+xml', 'Cache-Control': 'no-cache, max-age=300' } })
    }

    if (path === '/api/compare') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const urlsParam = url.searchParams.get('urls')
      if (!urlsParam) {
        return withJson({ error: 'urls parameter required (comma-separated)' }, { status: 400 })
      }

      const urlList = urlsParam.split(',').map(u => u.trim()).filter(Boolean)
      if (urlList.length === 0 || urlList.length > 5) {
        return withJson({ error: 'Provide 1-5 comma-separated URLs' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'compare')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      const comparisons: Array<{ url: string; statusCode: number; responseTimeMs: number; ssl: SslInfo }> = []
      for (const u of urlList) {
        const r = await checkUrl(u)
        comparisons.push({ url: r.url, statusCode: r.statusCode, responseTimeMs: r.responseTimeMs, ssl: r.ssl })
      }

      let fastest = comparisons[0]?.url || ''
      let slowest = comparisons[0]?.url || ''
      for (const c of comparisons) {
        if (c.responseTimeMs < (comparisons.find(x => x.url === fastest)?.responseTimeMs || Infinity)) fastest = c.url
        if (c.responseTimeMs > (comparisons.find(x => x.url === slowest)?.responseTimeMs || 0)) slowest = c.url
      }

      return withJson({ comparisons, fastest, slowest })
    }

    if (path === '/api/uptime') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const uptimeSeconds = Math.floor(process.uptime())
      const totalChecks = (db.prepare('SELECT COUNT(*) as c FROM checks').get() as any)?.c || 0
      const totalMonitors = (db.prepare("SELECT COUNT(*) as c FROM monitors WHERE status='active'").get() as any)?.c || 0
      const totalUsers = (db.prepare('SELECT COUNT(*) as c FROM api_keys').get() as any)?.c || 0
      const since24h = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString()
      const checksLast24h = (db.prepare('SELECT COUNT(*) as c FROM checks WHERE created_at >= ?').get(since24h) as any)?.c || 0

      return withJson({
        server_uptime_seconds: uptimeSeconds,
        total_checks: totalChecks,
        total_monitors: totalMonitors,
        total_users: totalUsers,
        checks_last_24h: checksLast24h,
      })
    }

    if (path === '/docs') {
      if (request.method !== 'GET') {
        return withCors('Method Not Allowed', { status: 405 })
      }

      const docsPage = '<!doctype html><html lang="en"><head><meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1.0"/><title>Pulse API Docs</title><style>:root{--bg:#090b10;--panel:#11141d;--text:#f7f9ff;--muted:#9aa4bf;--accent:#39c5ff;--border:#2a3040;--good:#3ddc97;--bad:#ff6378}*{box-sizing:border-box}body{margin:0;font-family:Inter,system-ui,sans-serif;background:var(--bg);color:var(--text);padding:2rem}.wrap{max-width:980px;margin:0 auto}h1{color:var(--accent);margin:0 0 .5rem}a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}.nav{display:flex;gap:1rem;align-items:center;margin-bottom:1.5rem}.ep{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:1rem;margin-bottom:1rem}.ep h3{margin:0 0 .3rem;color:var(--accent)}.ep .method{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.8rem;font-weight:700;margin-right:.5rem}.ep .method.get{background:#1a3a4a;color:#39c5ff}.ep .method.post{background:#1a4a2a;color:#3ddc97}.ep .method.delete{background:#4a1a1a;color:#ff6378}.ep .desc{color:var(--muted);margin:.3rem 0}.ep pre{background:#050913;border:1px solid var(--border);border-radius:8px;padding:.6rem;font-size:.82rem;overflow-x:auto;color:#d1dcff;white-space:pre-wrap}.ep .try-btn{background:linear-gradient(120deg,var(--accent),#7ce0ff);color:#071120;border:0;border-radius:8px;padding:.4rem .8rem;cursor:pointer;font-weight:600;font-size:.82rem;margin-top:.4rem}.ep .try-btn:hover{filter:brightness(1.05)}.ep .result{margin-top:.5rem;display:none;background:#050913;border:1px solid var(--border);border-radius:8px;padding:.6rem;font-size:.82rem;white-space:pre-wrap;color:#d1dcff;max-height:300px;overflow-y:auto}</style></head><body><div class="wrap"><div class="nav"><a href="/">&larr; Home</a><a href="/dashboard">Dashboard</a><a href="/status">Status</a><h1>Pulse API Documentation</h1></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/health</h3><p class="desc">Server health check. Returns status and uptime.</p><pre>curl -s http://147.93.131.124/api/health</pre><button class="try-btn" onclick="tryIt(this,\'/api/health\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/check?url=URL</h3><p class="desc">Full URL analysis — response time, status, headers, SSL, redirects.</p><pre>curl -s \'http://147.93.131.124/api/check?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/check?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/dns?domain=DOMAIN</h3><p class="desc">DNS record analysis — A, MX, TXT, NS, CNAME records.</p><pre>curl -s \'http://147.93.131.124/api/dns?domain=example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/dns?domain=example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/perf?url=URL</h3><p class="desc">Performance scoring — TTFB, total time, size, compression, score.</p><pre>curl -s \'http://147.93.131.124/api/perf?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/perf?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/seo?url=URL</h3><p class="desc">SEO audit — title, description, h1 count, images without alt, canonical, robots, score.</p><pre>curl -s \'http://147.93.131.124/api/seo?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/seo?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/compare?urls=URL1,URL2</h3><p class="desc">Side-by-side URL comparison — checks up to 5 URLs, returns fastest/slowest.</p><pre>curl -s \'http://147.93.131.124/api/compare?urls=https://example.com,https://google.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/compare?urls=https://example.com,https://google.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/uptime</h3><p class="desc">Global uptime statistics — server uptime, total checks, monitors, users, checks in last 24h.</p><pre>curl -s http://147.93.131.124/api/uptime</pre><button class="try-btn" onclick="tryIt(this,\'/api/uptime\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/headers?url=URL</h3><p class="desc">Security headers audit — checks 10 security headers (HSTS, CSP, X-Frame-Options, etc.) and returns a score.</p><pre>curl -s \'http://147.93.131.124/api/headers?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/headers?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/tech?url=URL</h3><p class="desc">Technology stack detection — identifies server software, frameworks, and technologies from headers and HTML.</p><pre>curl -s \'http://147.93.131.124/api/tech?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/tech?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/score?url=URL</h3><p class="desc">Aggregate site quality score — combines performance (30%), SEO (30%), and security (40%) into an overall score.</p><pre>curl -s \'http://147.93.131.124/api/score?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/score?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/sitemap?url=URL</h3><p class="desc">XML sitemap parser — fetches and parses sitemap XML, extracts all URLs from &lt;loc&gt; tags (max 100).</p><pre>curl -s \'http://147.93.131.124/api/sitemap?url=https://example.com/sitemap.xml\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/sitemap?url=https://example.com/sitemap.xml\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/ssl?url=URL</h3><p class="desc">Detailed SSL certificate monitor — issuer, expiry date, days until expiry, TLS protocol version, and expiry warnings.</p><pre>curl -s \'http://147.93.131.124/api/ssl?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/ssl?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/robots?url=URL</h3><p class="desc">Robots.txt parser — fetches and parses robots.txt, extracts User-agent, Allow, Disallow, Sitemap directives and Crawl-delay.</p><pre>curl -s \'http://147.93.131.124/api/robots?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/robots?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/mixed-content?url=URL</h3><p class="desc">Mixed content scanner — detects HTTP resources loaded on HTTPS pages, reports insecure src/href/action attributes.</p><pre>curl -s \'http://147.93.131.124/api/mixed-content?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/mixed-content?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/timeline?url=URL</h3><p class="desc">Response header timeline — traces redirect chain with per-hop timing, total hops, and total time.</p><pre>curl -s \'http://147.93.131.124/api/timeline?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/timeline?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/accessibility?url=URL</h3><p class="desc">Accessibility audit — checks for missing alt attributes, missing lang, empty links, missing form labels, skip navigation, ARIA landmarks, and h1. Returns issues array and score.</p><pre>curl -s \'http://147.93.131.124/api/accessibility?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/accessibility?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/cookies?url=URL</h3><p class="desc">Cookie scanner — extracts and classifies all Set-Cookie headers. Identifies tracking, session, and persistent cookies with secure/httpOnly/sameSite flags.</p><pre>curl -s \'http://147.93.131.124/api/cookies?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/cookies?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/weight?url=URL</h3><p class="desc">Page weight analyzer — calculates HTML size, counts scripts, stylesheets, images, fonts, and iframes. Returns resource breakdown and estimated weight.</p><pre>curl -s \'http://147.93.131.124/api/weight?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/weight?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/carbon?url=URL</h3><p class="desc">Carbon footprint estimator — calculates page transfer size and estimates CO2 emissions per page view. Rates pages as green, average, or dirty.</p><pre>curl -s \'http://147.93.131.124/api/carbon?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/carbon?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/links?url=URL</h3><p class="desc">Link checker — extracts all anchor tags from a page and classifies each link as internal or external.</p><pre>curl -s \'http://147.93.131.124/api/links?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/links?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/meta?url=URL</h3><p class="desc">Meta tag validator — checks Open Graph, Twitter Card, and standard meta tags. Reports missing tags and computes a completeness score.</p><pre>curl -s \'http://147.93.131.124/api/meta?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/meta?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/http2?url=URL</h3><p class="desc">HTTP/2 checker — detects HTTP/2 and HTTP/3 protocol support, reports alt-svc header for QUIC/H3 advertisement.</p><pre>curl -s \'http://147.93.131.124/api/http2?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/http2?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/structured-data?url=URL</h3><p class="desc">Structured data validator — extracts JSON-LD blocks and counts Microdata itemscope attributes. Reports @type and @context for each JSON-LD entry.</p><pre>curl -s \'http://147.93.131.124/api/structured-data?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/structured-data?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/dnsbl?url=URL</h3><p class="desc">DNS blacklist lookup — resolves domain IP and checks against Spamhaus, SpamCop, and Barracuda blacklists for spam reputation.</p><pre>curl -s \'http://147.93.131.124/api/dnsbl?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/dnsbl?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method post">POST</span>/api/batch</h3><p class="desc">Bulk URL analysis — accepts up to 10 URLs in JSON body.</p><pre>curl -s -X POST \'http://147.93.131.124/api/batch\' \\\n  -H \'Content-Type: application/json\' \\\n  -d \'{"urls":["https://example.com","https://google.com"]}\'</pre></div>'
        + '<div class="ep"><h3><span class="method post">POST</span>/api/test-webhook</h3><p class="desc">Webhook delivery test — sends test payload to provided URL.</p><pre>curl -s -X POST \'http://147.93.131.124/api/test-webhook\' \\\n  -H \'Content-Type: application/json\' \\\n  -d \'{"url":"https://httpbin.org/post"}\'</pre></div>'
        + '<div class="ep"><h3><span class="method post">POST</span>/api/register</h3><p class="desc">Register with email to receive an API key.</p><pre>curl -s -X POST \'http://147.93.131.124/api/register\' \\\n  -H \'Content-Type: application/json\' \\\n  -d \'{"email":"you@example.com"}\'</pre></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/account</h3><p class="desc">Account info — email, tier, checks today, limit. Requires X-API-Key header.</p><pre>curl -s http://147.93.131.124/api/account -H \'X-API-Key: YOUR_KEY\'</pre></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/history</h3><p class="desc">Last 50 checks for authenticated user. Requires X-API-Key header.</p><pre>curl -s http://147.93.131.124/api/history -H \'X-API-Key: YOUR_KEY\'</pre></div>'
        + '<div class="ep"><h3><span class="method post">POST</span>/api/subscribe</h3><p class="desc">Create Stripe checkout session for Pro tier ($9/month).</p><pre>curl -s -X POST \'http://147.93.131.124/api/subscribe\' \\\n  -H \'Content-Type: application/json\' \\\n  -d \'{"email":"you@example.com"}\'</pre></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/monitors</h3><p class="desc">List active monitors. Requires X-API-Key header.</p><pre>curl -s http://147.93.131.124/api/monitors -H \'X-API-Key: YOUR_KEY\'</pre></div>'
        + '<div class="ep"><h3><span class="method post">POST</span>/api/monitors</h3><p class="desc">Create a monitor (Pro tier). Requires X-API-Key header.</p><pre>curl -s -X POST http://147.93.131.124/api/monitors \\\n  -H \'X-API-Key: YOUR_KEY\' -H \'Content-Type: application/json\' \\\n  -d \'{"url":"https://example.com","interval_minutes":5,"alert_url":"https://webhook.site/test"}\'</pre></div>'
        + '<div class="ep"><h3><span class="method delete">DELETE</span>/api/monitors/:id</h3><p class="desc">Delete a monitor. Requires X-API-Key header.</p><pre>curl -s -X DELETE http://147.93.131.124/api/monitors/1 -H \'X-API-Key: YOUR_KEY\'</pre></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/monitors/:id/checks</h3><p class="desc">Last 100 checks for a specific monitor. Requires X-API-Key header.</p><pre>curl -s http://147.93.131.124/api/monitors/1/checks -H \'X-API-Key: YOUR_KEY\'</pre></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/badge/:id</h3><p class="desc">SVG uptime badge for a monitor — embed in README.</p><pre>curl -s http://147.93.131.124/api/badge/1\n# Embed: ![Uptime](http://147.93.131.124/api/badge/1)</pre><button class="try-btn" onclick="tryBadge(this,\'/api/badge/1\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method post">POST</span>/api/webhooks/stripe</h3><p class="desc">Stripe webhook handler for checkout.session.completed and subscription.deleted events.</p><pre># Handled automatically by Stripe</pre></div>'
        + '<script>function tryIt(btn,ep){var r=btn.nextElementSibling;r.style.display="block";r.textContent="Loading...";fetch(ep).then(function(res){return res.json()}).then(function(d){r.textContent=JSON.stringify(d,null,2)}).catch(function(e){r.textContent="Error: "+e.message})}function tryBadge(btn,ep){var r=btn.nextElementSibling;r.style.display="block";r.innerHTML="<img src=\\""+ep+"\\" alt=\\"badge\\"/>"}</script>'
        + '</div></body></html>'

      return withCors(docsPage, {
        status: 200,
        headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'public, max-age=300' },
      })
    }

    if (path === '/api/headers') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'headers')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const response = await fetch(normalized)
        const respHeaders = response.headers

        const securityHeaders = [
          'strict-transport-security',
          'x-content-type-options',
          'x-frame-options',
          'content-security-policy',
          'x-xss-protection',
          'referrer-policy',
          'permissions-policy',
          'cross-origin-opener-policy',
          'cross-origin-resource-policy',
          'cross-origin-embedder-policy',
        ]

        const found: Record<string, string> = {}
        const missing: string[] = []

        for (const h of securityHeaders) {
          const val = respHeaders.get(h)
          if (val) {
            found[h] = val
          } else {
            missing.push(h)
          }
        }

        const score = Object.keys(found).length * 10

        return withJson({ url: normalized, headers: found, missing, score })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Fetch failed'
        return withJson({ error: message }, { status: 502 })
      }
    }

    if (path === '/api/tech') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'tech')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const response = await fetch(normalized)
        const respHeaders = response.headers
        const html = await response.text()

        const serverHeader = respHeaders.get('server') || null
        const poweredBy = respHeaders.get('x-powered-by') || null
        const via = respHeaders.get('via') || null
        const generator = respHeaders.get('x-generator') || null

        const technologies: string[] = []
        const cookies: string[] = []

        const setCookies = respHeaders.getSetCookie ? respHeaders.getSetCookie() : []
        for (const c of setCookies) {
          const name = c.split('=')[0]?.trim()
          if (name) cookies.push(name)
        }

        if (serverHeader) {
          const sl = serverHeader.toLowerCase()
          if (sl.includes('cloudflare')) technologies.push('Cloudflare')
          if (sl.includes('nginx')) technologies.push('Nginx')
          if (sl.includes('apache')) technologies.push('Apache')
          if (sl.includes('caddy')) technologies.push('Caddy')
          if (sl.includes('iis')) technologies.push('IIS')
          if (sl.includes('litespeed')) technologies.push('LiteSpeed')
        }

        if (poweredBy) {
          const pl = poweredBy.toLowerCase()
          if (pl.includes('express')) technologies.push('Express')
          if (pl.includes('php')) technologies.push('PHP')
          if (pl.includes('asp.net')) technologies.push('ASP.NET')
          if (pl.includes('next.js')) technologies.push('Next.js')
        }

        const genMatch = html.match(/<meta\s+name=["']generator["']\s+content=["'](.*?)["']/i)
          || html.match(/<meta\s+content=["'](.*?)["']\s+name=["']generator["']/i)
        if (genMatch) technologies.push(genMatch[1])
        if (generator) technologies.push(generator)

        if (cookies.some(c => c.startsWith('__cf'))) technologies.push('Cloudflare')
        if (cookies.some(c => c.startsWith('wp-'))) technologies.push('WordPress')
        if (cookies.some(c => c === 'PHPSESSID')) technologies.push('PHP')
        if (cookies.some(c => c === 'JSESSIONID')) technologies.push('Java')

        const unique = [...new Set(technologies)]

        return withJson({ url: normalized, server: serverHeader, powered_by: poweredBy, via, technologies: unique, cookies })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Fetch failed'
        return withJson({ error: message }, { status: 502 })
      }
    }

    if (path === '/api/score') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'score')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const t0 = performance.now()
        const response = await fetch(normalized)
        const ttfb = performance.now() - t0
        const buf = await response.arrayBuffer()
        const totalMs = performance.now() - t0
        const sizeBytes = buf.byteLength
        const compressed = !!response.headers.get('content-encoding')
        const respHeaders = response.headers

        let perfScore = 100
        if (ttfb > 200) perfScore -= Math.floor((ttfb - 200) / 100)
        if (sizeBytes > 500 * 1024) perfScore -= Math.floor((sizeBytes - 500 * 1024) / (50 * 1024))
        if (!compressed) perfScore -= 10
        perfScore = Math.max(0, Math.min(100, perfScore))

        const htmlText = new TextDecoder().decode(buf)
        const titleMatch = htmlText.match(/<title>(.*?)<\/title>/i)
        const descMatch = htmlText.match(/<meta\s+name=["']description["']\s+content=["'](.*?)["']/i)
          || htmlText.match(/<meta\s+content=["'](.*?)["']\s+name=["']description["']/i)
        const canonicalMatch = htmlText.match(/<link\s[^>]*rel=["']canonical["'][^>]*href=["'](.*?)["']/i)
        const imgTags = htmlText.match(/<img\s[^>]*>/gi) || []
        let imgsNoAlt = 0
        for (const img of imgTags) { if (!/\balt\s*=/i.test(img)) imgsNoAlt++ }

        let seoScore = 100
        if (!titleMatch) seoScore -= 10
        if (!descMatch) seoScore -= 10
        seoScore -= imgsNoAlt * 5
        if (!canonicalMatch) seoScore -= 10
        seoScore = Math.max(0, Math.min(100, seoScore))

        const secHeaders = ['strict-transport-security', 'x-content-type-options', 'x-frame-options', 'content-security-policy', 'x-xss-protection', 'referrer-policy', 'permissions-policy', 'cross-origin-opener-policy', 'cross-origin-resource-policy', 'cross-origin-embedder-policy']
        let secFound = 0
        for (const h of secHeaders) { if (respHeaders.get(h)) secFound++ }
        const securityScore = secFound * 10

        const overallScore = Math.round(perfScore * 0.3 + seoScore * 0.3 + securityScore * 0.4)

        return withJson({
          url: normalized,
          performance_score: perfScore,
          seo_score: seoScore,
          security_score: securityScore,
          overall_score: overallScore,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Fetch failed'
        return withJson({ error: message }, { status: 502 })
      }
    }

    if (path === '/api/sitemap') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'sitemap')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const response = await fetch(normalized)
        const xml = await response.text()

        const locMatches = xml.match(/<loc>(.*?)<\/loc>/gi) || []
        const urls: string[] = []
        for (const m of locMatches) {
          const inner = m.replace(/<\/?loc>/gi, '').trim()
          if (inner && urls.length < 100) urls.push(inner)
        }

        return withJson({
          url: normalized,
          urls_found: locMatches.length,
          urls,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Fetch failed'
        return withJson({ error: message }, { status: 502 })
      }
    }

    if (path === '/api/ssl') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'ssl')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const parsedUrl = new URL(normalized)

        if (parsedUrl.protocol !== 'https:') {
          return withJson({ url: normalized, valid: false, issuer: null, expires_at: null, days_until_expiry: null, protocol: null, warning: 'not_https' })
        }

        const host = parsedUrl.hostname
        const port = parsedUrl.port ? Number(parsedUrl.port) : 443

        const sslResult = await new Promise<{ valid: boolean; issuer: string | null; expires_at: string | null; days_until_expiry: number | null; protocol: string | null; warning: string | null }>((resolve) => {
          let settled = false
          const finalize = (val: any) => { if (settled) return; settled = true; socket.end(); resolve(val) }

          const socket = tls.connect({ host, port, servername: host, rejectUnauthorized: false })

          socket.once('secureConnect', () => {
            try {
              const cert = socket.getPeerCertificate(true) as any
              const proto = socket.getProtocol?.() || null

              if (!cert || Object.keys(cert).length === 0) {
                finalize({ valid: false, issuer: null, expires_at: null, days_until_expiry: null, protocol: proto, warning: 'no_certificate' })
                return
              }

              const expiry = cert.valid_to ? new Date(cert.valid_to) : null
              let valid = true
              let daysUntil: number | null = null
              let warning: string | null = null

              if (expiry && !Number.isNaN(expiry.getTime())) {
                daysUntil = Math.floor((expiry.getTime() - Date.now()) / (1000 * 60 * 60 * 24))
                if (daysUntil < 0) { valid = false; warning = 'expired' }
                else if (daysUntil < 30) { warning = 'expires_soon' }
              } else {
                valid = false
              }

              try { tls.checkServerIdentity(host, cert) } catch { valid = false }

              finalize({
                valid,
                issuer: extractIssuer(cert),
                expires_at: cert.valid_to || null,
                days_until_expiry: daysUntil,
                protocol: proto,
                warning,
              })
            } catch {
              finalize({ valid: false, issuer: null, expires_at: null, days_until_expiry: null, protocol: null, warning: 'parse_error' })
            }
          })

          socket.once('error', () => {
            finalize({ valid: false, issuer: null, expires_at: null, days_until_expiry: null, protocol: null, warning: 'connection_error' })
          })

          socket.setTimeout(5000, () => {
            finalize({ valid: false, issuer: null, expires_at: null, days_until_expiry: null, protocol: null, warning: 'timeout' })
            socket.destroy(new Error('SSL timeout'))
          })
        })

        return withJson({ url: normalized, ...sslResult })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'SSL check failed'
        return withJson({ error: message }, { status: 502 })
      }
    }

    if (path === '/api/robots') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'robots')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const parsedUrl = new URL(normalized)
        const robotsUrl = parsedUrl.origin + '/robots.txt'

        const resp = await fetch(robotsUrl, { redirect: 'follow', signal: AbortSignal.timeout(10000) })
        if (!resp.ok) {
          return withJson({ url: robotsUrl, user_agents: [], disallow: [], allow: [], sitemaps: [], crawl_delay: null, error: 'robots.txt returned ' + resp.status })
        }

        const text = await resp.text()
        const lines = text.split('\n')
        const userAgents: string[] = []
        const disallow: string[] = []
        const allow: string[] = []
        const sitemaps: string[] = []
        let crawlDelay: number | null = null

        for (const raw of lines) {
          const line = raw.trim()
          const lower = line.toLowerCase()
          if (lower.startsWith('user-agent:')) {
            const val = line.slice(11).trim()
            if (val && !userAgents.includes(val)) userAgents.push(val)
          } else if (lower.startsWith('disallow:')) {
            const val = line.slice(9).trim()
            if (val && !disallow.includes(val)) disallow.push(val)
          } else if (lower.startsWith('allow:')) {
            const val = line.slice(6).trim()
            if (val && !allow.includes(val)) allow.push(val)
          } else if (lower.startsWith('sitemap:')) {
            const val = line.slice(8).trim()
            if (val && !sitemaps.includes(val)) sitemaps.push(val)
          } else if (lower.startsWith('crawl-delay:')) {
            const val = parseInt(line.slice(12).trim(), 10)
            if (!Number.isNaN(val)) crawlDelay = val
          }
        }

        return withJson({ url: robotsUrl, user_agents: userAgents, disallow, allow, sitemaps, crawl_delay: crawlDelay })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to fetch robots.txt'
        return withJson({ error: message }, { status: 502 })
      }
    }

    if (path === '/api/mixed-content') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'mixed-content')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const parsedUrl = new URL(normalized)
        const isHttps = parsedUrl.protocol === 'https:'

        const resp = await fetch(normalized, { redirect: 'follow', signal: AbortSignal.timeout(10000) })
        const html = await resp.text()

        const resourceRegex = /(?:src|href|action)\s*=\s*["']([^"']+)["']/gi
        const allResources: string[] = []
        const httpResources: string[] = []
        let match: RegExpExecArray | null

        while ((match = resourceRegex.exec(html)) !== null) {
          const resource = match[1]
          if (resource.startsWith('http://') || resource.startsWith('https://') || resource.startsWith('//')) {
            allResources.push(resource)
            if (isHttps && resource.startsWith('http://')) {
              httpResources.push(resource)
            }
          }
        }

        return withJson({
          url: normalized,
          is_https: isHttps,
          mixed_content_found: httpResources.length > 0,
          http_resources: httpResources,
          total_resources: allResources.length,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to scan for mixed content'
        return withJson({ error: message }, { status: 502 })
      }
    }

    if (path === '/api/timeline') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'timeline')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const hops: Array<{ url: string; status: number; time_ms: number }> = []
        let currentUrl = normalized
        const maxHops = 10

        for (let i = 0; i < maxHops; i++) {
          const start = performance.now()
          const resp = await fetch(currentUrl, { redirect: 'manual', signal: AbortSignal.timeout(10000) })
          const elapsed = Math.round(performance.now() - start)

          hops.push({ url: currentUrl, status: resp.status, time_ms: elapsed })

          if (resp.status >= 300 && resp.status < 400) {
            const location = resp.headers.get('location')
            if (!location) break
            currentUrl = location.startsWith('http') ? location : new URL(location, currentUrl).href
          } else {
            break
          }
        }

        const totalTime = hops.reduce((sum, h) => sum + h.time_ms, 0)

        return withJson({
          url: normalized,
          hops,
          total_hops: hops.length,
          total_time_ms: totalTime,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to trace redirect timeline'
        return withJson({ error: message }, { status: 502 })
      }
    }

    if (path === '/api/accessibility') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'accessibility')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const resp = await fetch(normalized, { signal: AbortSignal.timeout(15000) })
        const html = await resp.text()

        const issues: Array<{ type: string; element: string; count: number }> = []
        let score = 100

        const imgsAll = html.match(/<img\b[^>]*>/gi) || []
        const imgsMissingAlt = imgsAll.filter(tag => !tag.match(/alt\s*=/i))
        if (imgsMissingAlt.length > 0) {
          issues.push({ type: 'missing_alt', element: 'img', count: imgsMissingAlt.length })
          score -= Math.min(imgsMissingAlt.length * 5, 20)
        }

        const hasLang = /<html[^>]+lang\s*=/i.test(html)
        if (!hasLang) {
          issues.push({ type: 'missing_lang', element: 'html', count: 1 })
          score -= 15
        }

        const emptyLinks = (html.match(/<a\b[^>]*>\s*<\/a>/gi) || []).length
        if (emptyLinks > 0) {
          issues.push({ type: 'empty_links', element: 'a', count: emptyLinks })
          score -= Math.min(emptyLinks * 3, 15)
        }

        const formInputs = html.match(/<input\b[^>]*>/gi) || []
        const labels = html.match(/<label\b/gi) || []
        if (formInputs.length > 0 && labels.length < formInputs.length) {
          const missing = formInputs.length - labels.length
          issues.push({ type: 'missing_form_labels', element: 'input', count: missing })
          score -= Math.min(missing * 5, 15)
        }

        const hasSkipNav = /skip[- ]?nav|skip[- ]?to[- ]?content|skip[- ]?link/i.test(html)
        if (!hasSkipNav) {
          issues.push({ type: 'missing_skip_navigation', element: 'body', count: 1 })
          score -= 10
        }

        const hasMainLandmark = /<main\b/i.test(html) || /role\s*=\s*["']main["']/i.test(html)
        const hasNavLandmark = /<nav\b/i.test(html) || /role\s*=\s*["']navigation["']/i.test(html)
        if (!hasMainLandmark) {
          issues.push({ type: 'missing_landmark_main', element: 'body', count: 1 })
          score -= 10
        }
        if (!hasNavLandmark) {
          issues.push({ type: 'missing_landmark_nav', element: 'body', count: 1 })
          score -= 5
        }

        const hasH1 = /<h1\b/i.test(html)
        if (!hasH1) {
          issues.push({ type: 'missing_h1', element: 'body', count: 1 })
          score -= 10
        }

        score = Math.max(score, 0)
        const totalIssues = issues.reduce((sum, i) => sum + i.count, 0)

        return withJson({
          url: normalized,
          issues,
          total_issues: totalIssues,
          score,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to audit accessibility'
        return withJson({ error: message }, { status: 502 })
      }
    }

    if (path === '/api/cookies') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'cookies')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const resp = await fetch(normalized, { signal: AbortSignal.timeout(15000) })
        const setCookies = resp.headers.getSetCookie() || []

        const trackingPatterns = /^(_ga|_gid|_fbp|_fbc|_gcl|__utm|_hjid|_hjSession|_hj|mp_|_mkto|hubspot|__hssc|__hstc|__hsfp|_clck|_clsk|_uetv|_uetvid|IDE|DSID|NID|APISID|SSID|SAPISID)/i
        const cookies: Array<{
          name: string
          domain: string | null
          path: string
          secure: boolean
          httpOnly: boolean
          sameSite: string | null
          type: string
          expires: string | null
        }> = []

        let trackingCount = 0
        let sessionCount = 0

        for (const raw of setCookies) {
          const parts = raw.split(';').map(p => p.trim())
          const [nameVal] = parts
          const eqIdx = nameVal.indexOf('=')
          const name = eqIdx > -1 ? nameVal.slice(0, eqIdx).trim() : nameVal.trim()

          let domain: string | null = null
          let path = '/'
          let secure = false
          let httpOnly = false
          let sameSite: string | null = null
          let expires: string | null = null

          for (const part of parts.slice(1)) {
            const lower = part.toLowerCase()
            if (lower.startsWith('domain=')) domain = part.slice(7).trim()
            else if (lower.startsWith('path=')) path = part.slice(5).trim()
            else if (lower === 'secure') secure = true
            else if (lower === 'httponly') httpOnly = true
            else if (lower.startsWith('samesite=')) sameSite = part.slice(9).trim()
            else if (lower.startsWith('expires=')) expires = part.slice(8).trim()
            else if (lower.startsWith('max-age=')) {
              const maxAge = parseInt(part.slice(8).trim(), 10)
              if (!isNaN(maxAge)) expires = new Date(Date.now() + maxAge * 1000).toISOString()
            }
          }

          const isTracking = trackingPatterns.test(name)
          const isSession = !expires
          const type = isTracking ? 'tracking' : isSession ? 'session' : 'persistent'
          if (isTracking) trackingCount++
          if (isSession) sessionCount++

          cookies.push({ name, domain, path, secure, httpOnly, sameSite, type, expires })
        }

        return withJson({
          url: normalized,
          cookies,
          total: cookies.length,
          tracking_count: trackingCount,
          session_count: sessionCount,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to scan cookies'
        return withJson({ error: message }, { status: 502 })
      }
    }

    if (path === '/api/weight') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'weight')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const resp = await fetch(normalized, { signal: AbortSignal.timeout(15000) })
        const html = await resp.text()
        const htmlSizeBytes = new TextEncoder().encode(html).length

        const scripts = (html.match(/<script\b[^>]*src\s*=/gi) || []).length
        const inlineScripts = (html.match(/<script\b[^>]*>[\s\S]*?<\/script>/gi) || []).filter(s => !s.match(/src\s*=/i)).length
        const stylesheets = (html.match(/<link\b[^>]*rel\s*=\s*["']stylesheet["'][^>]*>/gi) || []).length
        const inlineStyles = (html.match(/<style\b[^>]*>[\s\S]*?<\/style>/gi) || []).length
        const images = (html.match(/<img\b[^>]*>/gi) || []).length
        const fonts = (html.match(/<link\b[^>]*rel\s*=\s*["']preload["'][^>]*as\s*=\s*["']font["'][^>]*>/gi) || []).length
            + (html.match(/url\s*\([^)]*\.(woff2?|ttf|otf|eot)/gi) || []).length
        const iframes = (html.match(/<iframe\b[^>]*>/gi) || []).length

        const totalResources = scripts + inlineScripts + stylesheets + inlineStyles + images + fonts + iframes
        const estimatedWeightKb = Math.round(htmlSizeBytes / 1024)

        return withJson({
          url: normalized,
          html_size_bytes: htmlSizeBytes,
          total_resources: totalResources,
          scripts: scripts + inlineScripts,
          stylesheets: stylesheets + inlineStyles,
          images,
          fonts,
          iframes,
          estimated_weight_kb: estimatedWeightKb,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to analyze page weight'
        return withJson({ error: message }, { status: 502 })
      }
    }

    if (path === '/api/carbon') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'carbon')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const resp = await fetch(normalized, { signal: AbortSignal.timeout(15000) })
        const body = await resp.arrayBuffer()
        const transferSizeBytes = body.byteLength
        const transferSizeKB = transferSizeBytes / 1024
        const co2Grams = Math.round(transferSizeKB * 0.0002 * 1000 * 100) / 100
        let rating = 'average'
        if (co2Grams < 0.5) rating = 'green'
        else if (co2Grams > 1.0) rating = 'dirty'
        const cleanerThanPercent = co2Grams < 0.5 ? 85 : co2Grams < 1.0 ? 50 : 15

        return withJson({
          url: normalized,
          transfer_size_bytes: transferSizeBytes,
          co2_grams: co2Grams,
          rating,
          cleaner_than_percent: cleanerThanPercent,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to estimate carbon footprint'
        return withJson({ error: message }, { status: 502 })
      }
    }

    if (path === '/api/links') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'links')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const resp = await fetch(normalized, { signal: AbortSignal.timeout(15000) })
        const html = await resp.text()
        const targetHost = new URL(normalized).hostname
        const linkRegex = /<a\b[^>]*href\s*=\s*["']([^"'#][^"']*)["'][^>]*>([\s\S]*?)<\/a>/gi
        const links: Array<{ href: string; text: string; type: string }> = []
        let match
        while ((match = linkRegex.exec(html)) !== null) {
          const href = match[1].trim()
          const text = match[2].replace(/<[^>]*>/g, '').trim()
          let type = 'external'
          try {
            const linkUrl = new URL(href, normalized)
            if (linkUrl.hostname === targetHost) type = 'internal'
          } catch {
            type = 'internal'
          }
          links.push({ href, text, type })
        }
        const internal = links.filter(l => l.type === 'internal').length
        const external = links.filter(l => l.type === 'external').length

        return withJson({
          url: normalized,
          links,
          total: links.length,
          internal,
          external,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to extract links'
        return withJson({ error: message }, { status: 502 })
      }
    }

    if (path === '/api/meta') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'meta')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const resp = await fetch(normalized, { signal: AbortSignal.timeout(15000) })
        const html = await resp.text()

        const titleMatch = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i)
        const title = titleMatch ? titleMatch[1].trim() : null

        const descMatch = html.match(/<meta\b[^>]*name\s*=\s*["']description["'][^>]*content\s*=\s*["']([^"']*)["']/i)
          || html.match(/<meta\b[^>]*content\s*=\s*["']([^"']*)["'][^>]*name\s*=\s*["']description["']/i)
        const description = descMatch ? descMatch[1].trim() : null

        const ogExtract = (prop: string): string | null => {
          const re = new RegExp('<meta\\b[^>]*property\\s*=\\s*["\']og:' + prop + '["\'][^>]*content\\s*=\\s*["\']([^"\']*)["\']', 'i')
          const re2 = new RegExp('<meta\\b[^>]*content\\s*=\\s*["\']([^"\']*)["\'][^>]*property\\s*=\\s*["\']og:' + prop + '["\']', 'i')
          const m = html.match(re) || html.match(re2)
          return m ? m[1].trim() : null
        }

        const twExtract = (name: string): string | null => {
          const re = new RegExp('<meta\\b[^>]*name\\s*=\\s*["\']twitter:' + name + '["\'][^>]*content\\s*=\\s*["\']([^"\']*)["\']', 'i')
          const re2 = new RegExp('<meta\\b[^>]*content\\s*=\\s*["\']([^"\']*)["\'][^>]*name\\s*=\\s*["\']twitter:' + name + '["\']', 'i')
          const m = html.match(re) || html.match(re2)
          return m ? m[1].trim() : null
        }

        const og = {
          title: ogExtract('title'),
          description: ogExtract('description'),
          image: ogExtract('image'),
          url: ogExtract('url'),
        }

        const twitter = {
          card: twExtract('card'),
          title: twExtract('title'),
          description: twExtract('description'),
          image: twExtract('image'),
        }

        const missing: string[] = []
        if (!title) missing.push('title')
        if (!description) missing.push('description')
        if (!og.title) missing.push('og:title')
        if (!og.description) missing.push('og:description')
        if (!og.image) missing.push('og:image')
        if (!og.url) missing.push('og:url')
        if (!twitter.card) missing.push('twitter:card')
        if (!twitter.title) missing.push('twitter:title')
        if (!twitter.description) missing.push('twitter:description')
        if (!twitter.image) missing.push('twitter:image')

        const totalFields = 10
        const presentFields = totalFields - missing.length
        const score = Math.round((presentFields / totalFields) * 100)

        return withJson({
          url: normalized,
          title,
          description,
          og,
          twitter,
          missing,
          score,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to validate meta tags'
        return withJson({ error: message }, { status: 502 })
      }
    }

    if (path === '/api/http2') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'http2')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const resp = await fetch(normalized, { signal: AbortSignal.timeout(15000) })
        const httpVersion = resp.headers.get('version') || null
        const altSvc = resp.headers.get('alt-svc') || null
        const supportsHttp3 = altSvc ? /h3/i.test(altSvc) : false
        const supportsHttp2 = resp.url.startsWith('https://') ? true : false

        return withJson({
          url: normalized,
          http_version: supportsHttp2 ? 'h2' : 'http/1.1',
          supports_http2: supportsHttp2,
          supports_http3: supportsHttp3,
          alt_svc: altSvc,
          status_code: resp.status,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to check HTTP/2 support'
        return withJson({ error: message }, { status: 502 })
      }
    }

    if (path === '/api/structured-data') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'structured-data')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const resp = await fetch(normalized, { signal: AbortSignal.timeout(15000) })
        const html = await resp.text()

        const jsonLdBlocks: Array<{ type: string | null; context: string | null; raw: unknown }> = []
        const ldRegex = /<script\b[^>]*type\s*=\s*["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi
        let ldMatch
        while ((ldMatch = ldRegex.exec(html)) !== null) {
          try {
            const parsed = JSON.parse(ldMatch[1])
            jsonLdBlocks.push({
              type: parsed['@type'] || null,
              context: parsed['@context'] || null,
              raw: parsed,
            })
          } catch {
            jsonLdBlocks.push({ type: null, context: null, raw: ldMatch[1].trim() })
          }
        }

        const microdataCount = (html.match(/\bitemscope\b/gi) || []).length

        const totalItems = jsonLdBlocks.length + microdataCount
        const score = totalItems > 0 ? Math.min(100, totalItems * 25) : 0

        return withJson({
          url: normalized,
          json_ld: jsonLdBlocks,
          json_ld_count: jsonLdBlocks.length,
          microdata_count: microdataCount,
          score,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to extract structured data'
        return withJson({ error: message }, { status: 502 })
      }
    }

    if (path === '/api/dnsbl') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'dnsbl')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const hostname = new URL(normalized).hostname
        const addresses = await dnsResolve(hostname, 'A') as string[]
        const ip = addresses[0] || null

        if (!ip) {
          return withJson({ error: 'Could not resolve IP for ' + hostname }, { status: 400 })
        }

        const reversed = ip.split('.').reverse().join('.')
        const blacklists = ['zen.spamhaus.org', 'bl.spamcop.net', 'b.barracudacentral.org']
        const listedOn: string[] = []

        for (const bl of blacklists) {
          try {
            const lookup = reversed + '.' + bl
            await dnsResolve(lookup, 'A')
            listedOn.push(bl)
          } catch {
            // Not listed — DNS resolution fails when not blacklisted
          }
        }

        return withJson({
          url: normalized,
          ip,
          blacklists_checked: blacklists.length,
          blacklisted: listedOn.length > 0,
          listed_on: listedOn,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to check DNS blacklists'
        return withJson({ error: message }, { status: 502 })
      }
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

        const newCode = result.statusCode
        const oldCode = mon.last_status_code as number | null

        if (mon.alert_url) {
          const alertPayload = (status: string, code: number) => ({
            monitor_id: mon.id,
            url: mon.url,
            status,
            status_code: code,
            checked_at: new Date().toISOString(),
          })

          if (oldCode === 200 && newCode !== 200) {
            if (mon.alert_url.startsWith('mailto:')) {
              const email = mon.alert_url.slice(7)
              sendAlertEmail(email, '[Pulse] ' + mon.url + ' is DOWN', 'Monitor ' + mon.id + ' detected ' + mon.url + ' is DOWN (status ' + newCode + ') at ' + new Date().toISOString()).catch(() => {})
            } else {
              fetch(mon.alert_url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(alertPayload('down', newCode)),
              }).catch(() => {})
            }
          } else if (oldCode !== null && oldCode !== 200 && newCode === 200) {
            if (mon.alert_url.startsWith('mailto:')) {
              const email = mon.alert_url.slice(7)
              sendAlertEmail(email, '[Pulse] ' + mon.url + ' is UP', 'Monitor ' + mon.id + ' detected ' + mon.url + ' is back UP (status 200) at ' + new Date().toISOString()).catch(() => {})
            } else {
              fetch(mon.alert_url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(alertPayload('up', 200)),
              }).catch(() => {})
            }
          }
        }

        updateMonitorStatusCodeStmt.run(newCode, mon.id)
      } catch {}
    }
  }
}, 60000)

function sendDailyReport(email: string, monitors: Array<{ id: number; url: string; last_status_code: number | null }>): void {
  const lines = ['Pulse Daily Report — ' + new Date().toISOString().slice(0, 10), '']
  for (const m of monitors) {
    const status = m.last_status_code === 200 ? 'UP' : m.last_status_code ? 'DOWN (' + m.last_status_code + ')' : 'PENDING'
    lines.push('Monitor #' + m.id + ' — ' + m.url + ' — ' + status)
  }
  lines.push('', 'View dashboard: http://147.93.131.124/dashboard')
  const body = lines.join('\n')
  const subject = '[Pulse] Daily Report — ' + monitors.length + ' monitors'
  sendAlertEmail(email, subject, body).catch(() => {})
}

setInterval(() => {
  const allMonitors = db.prepare("SELECT id, api_key, url, last_status_code, alert_url FROM monitors WHERE status = 'active'").all() as Array<{ id: number; api_key: string; url: string; last_status_code: number | null; alert_url: string | null }>
  const byKey: Record<string, Array<{ id: number; url: string; last_status_code: number | null; email: string }>> = {}
  for (const m of allMonitors) {
    if (!m.alert_url || !m.alert_url.startsWith('mailto:')) continue
    const email = m.alert_url.slice(7)
    if (!byKey[email]) byKey[email] = []
    byKey[email].push({ id: m.id, url: m.url, last_status_code: m.last_status_code })
  }
  let count = 0
  for (const [email, monitors] of Object.entries(byKey)) {
    sendDailyReport(email, monitors)
    count++
  }
  console.log('[report] Sent daily reports to ' + count + ' users')
}, 24 * 60 * 60 * 1000)

setInterval(async () => {
  try {
    const result = await checkUrl('https://example.com')
    const line = '[' + new Date().toISOString() + '] status=' + result.statusCode + ' time=' + result.responseTimeMs + 'ms url=' + result.url + '\n'
    appendFileSync('/root/opus-orchestrator/logs/health-cron.log', line)
    console.log('[cron] Health check written to log: status=' + result.statusCode)
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'unknown'
    appendFileSync('/root/opus-orchestrator/logs/health-cron.log', '[' + new Date().toISOString() + '] ERROR: ' + msg + '\n')
    console.log('[cron] Health check failed: ' + msg)
  }
}, 12 * 60 * 60 * 1000)

console.log(`Pulse — Site Intelligence API running on http://localhost:${PORT}`)
console.log(`Port open in server: ${server.port}`)
