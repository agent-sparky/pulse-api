import tls from 'node:tls'
import { randomBytes, createHash } from 'node:crypto'
import { resolve as dnsResolve, Resolver } from 'node:dns/promises'
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
      <p><strong>Open Graph Image Preview:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/og-image?url=https://example.com'</pre>
      <p><strong>HTML Validator:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/html-validate?url=https://example.com'</pre>
      <p><strong>Favicon Checker:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/favicon?url=https://example.com'</pre>
      <p><strong>Lighthouse Audit:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/lighthouse?url=https://example.com'</pre>
      <p><strong>CSP Analyzer:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/csp?url=https://example.com'</pre>
      <p><strong>Response Headers Inspector:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/response-headers?url=https://example.com'</pre>
      <p><strong>SRI Checker:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/sri?url=https://example.com'</pre>
      <p><strong>Cookie Consent Detector:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/cookie-consent?url=https://example.com'</pre>
      <p><strong>TLS Cipher Suite Analyzer:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/tls-ciphers?url=https://example.com'</pre>
      <p><strong>HSTS Preload Checker:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/hsts-preload?url=https://example.com'</pre>
      <p><strong>WebSocket Detector:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/websocket?url=https://example.com'</pre>
      <p><strong>DNS Propagation Checker:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/dns-propagation?url=https://example.com'</pre>
      <p><strong>Permissions-Policy Analyzer:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/permissions-policy?url=https://example.com'</pre>
      <p><strong>CORS Tester:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/cors-test?url=https://example.com'</pre>
      <p><strong>WAF Detector:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/waf?url=https://example.com'</pre>
      <p><strong>Cache Analysis:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/cache-analysis?url=https://example.com'</pre>
      <p><strong>Security.txt Checker:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/security-txt?url=https://example.com'</pre>
      <p><strong>WHOIS Lookup:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/whois?url=https://example.com'</pre>
      <p><strong>Content-Encoding Analyzer:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/content-encoding?url=https://example.com'</pre>
      <p><strong>Referrer-Policy Checker:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/referrer-policy?url=https://example.com'</pre>
      <p><strong>X-Frame-Options Tester:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/x-frame-options?url=https://example.com'</pre>
      <p><strong>Subdomain Enumerator:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/subdomains?url=https://example.com'</pre>
      <p><strong>HTTP Method Tester:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/http-methods?url=https://example.com'</pre>
      <p><strong>Server Banner Analyzer:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/server-banner?url=https://example.com'</pre>
      <p><strong>Email Harvester:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/emails?url=https://example.com'</pre>
      <p><strong>Port Scanner Lite:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/open-ports?url=https://example.com'</pre>
      <p><strong>DNS Record Diff:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/dns-diff?url1=https://example.com&url2=https://google.com'</pre>
      <p><strong>Email Obfuscation Detector:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/email-obfuscation?url=https://example.com'</pre>
      <p><strong>Header Timeline:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/header-timeline?url=https://example.com'</pre>
      <p><strong>Domain Age Checker:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/domain-age?url=https://example.com'</pre>
      <p><strong>JWT Token Decoder:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/jwt-decode?url=https://example.com'</pre>
      <p><strong>API Usage Analytics:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/analytics' -H 'X-API-Key: YOUR_KEY'</pre>
      <p><strong>Webhook Retry:</strong></p>
      <pre>curl -s -X POST 'http://147.93.131.124/api/webhook-retry' -H 'Content-Type: application/json' -d '{"url":"https://httpbin.org/post","payload":{"test":true}}'</pre>
      <p><strong>OpenAPI Spec:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/openapi'</pre>
      <p><strong>Rate Limits:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/rate-limits' -H 'X-API-Key: YOUR_KEY'</pre>
      <p><strong>IP Geolocation:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/geoip?url=https://example.com'</pre>
      <p><strong>URL Metadata Preview:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/screenshot?url=https://example.com'</pre>
      <p><strong>Sitemap Generator:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/sitemap-gen?url=https://example.com'</pre>
      <p><strong>DNS over HTTPS:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/doh?url=https://example.com'</pre>
      <p><strong>Robots Meta Tag Analyzer:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/robots-meta?url=https://example.com'</pre>
      <p><strong>SSL Chain Validator:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/ssl-chain?url=https://example.com'</pre>
      <p><strong>HTTP Header Fingerprint:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/header-fingerprint?url=https://example.com'</pre>
      <p><strong>Content-Type Sniffer:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/content-type?url=https://example.com'</pre>
      <p><strong>Cookie Security Audit:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/cookie-security?url=https://example.com'</pre>
      <p><strong>DNS CAA Record Checker:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/dns-caa?url=https://example.com'</pre>
      <p><strong>SRI Scanner:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/sri-scan?url=https://example.com'</pre>
      <p><strong>HSTS Deep Analysis:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/hsts-analysis?url=https://example.com'</pre>
      <p><strong>DNS MX Record Checker:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/dns-mx?url=https://example.com'</pre>
      <p><strong>CT Log Checker:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/ct-logs?url=https://example.com'</pre>
      <p><strong>HTTP/3 Detector:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/http3?url=https://example.com'</pre>
      <p><strong>DMARC Record Analyzer:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/dns-dmarc?url=https://example.com'</pre>
      <p><strong>SPF Record Analyzer:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/dns-spf?url=https://example.com'</pre>
      <p><strong>NS Record Checker:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/dns-ns?url=https://example.com'</pre>
      <p><strong>AAAA Record Checker:</strong></p>
      <pre>curl -s 'http://147.93.131.124/api/dns-aaaa?url=https://example.com'</pre>
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
        + '<div class="ep"><h3><span class="method get">GET</span>/api/og-image?url=URL</h3><p class="desc">Open Graph image preview — extracts og:image, og:title, og:description, og:type, and og:site_name meta tags from any page.</p><pre>curl -s \'http://147.93.131.124/api/og-image?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/og-image?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/html-validate?url=URL</h3><p class="desc">HTML validator — checks for missing doctype, lang, title, charset, viewport, alt attributes, duplicate IDs, head, and body tags. Returns issues array and score.</p><pre>curl -s \'http://147.93.131.124/api/html-validate?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/html-validate?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/favicon?url=URL</h3><p class="desc">Favicon checker — detects link rel="icon", shortcut icon, and apple-touch-icon tags. Falls back to /favicon.ico HEAD check. Returns all favicons with href, rel, type, and sizes.</p><pre>curl -s \'http://147.93.131.124/api/favicon?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/favicon?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/lighthouse?url=URL</h3><p class="desc">Lighthouse audit — computes performance, accessibility, SEO, and security scores inline. Returns overall score and letter grade (A-F).</p><pre>curl -s \'http://147.93.131.124/api/lighthouse?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/lighthouse?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/csp?url=URL</h3><p class="desc">CSP analyzer — parses Content-Security-Policy header, extracts directives, detects unsafe-inline and unsafe-eval, and computes a security score.</p><pre>curl -s \'http://147.93.131.124/api/csp?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/csp?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/response-headers?url=URL</h3><p class="desc">Response headers inspector — returns all response headers annotated with category (security, caching, cors, server, content, custom).</p><pre>curl -s \'http://147.93.131.124/api/response-headers?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/response-headers?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/sri?url=URL</h3><p class="desc">Subresource Integrity checker — scans script and stylesheet tags for SRI integrity attributes. Returns resource list and coverage score.</p><pre>curl -s \'http://147.93.131.124/api/sri?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/sri?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/cookie-consent?url=URL</h3><p class="desc">Cookie consent detector — scans for GDPR consent banners, detects platforms (OneTrust, CookieBot, etc.), and identifies privacy signals.</p><pre>curl -s \'http://147.93.131.124/api/cookie-consent?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/cookie-consent?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/tls-ciphers?url=URL</h3><p class="desc">TLS cipher suite analyzer — connects to host and reports negotiated cipher, protocol version, key bits, and security warnings.</p><pre>curl -s \'http://147.93.131.124/api/tls-ciphers?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/tls-ciphers?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/hsts-preload?url=URL</h3><p class="desc">HSTS preload checker — inspects Strict-Transport-Security header for max-age, includeSubDomains, and preload directives. Reports preload readiness and score.</p><pre>curl -s \'http://147.93.131.124/api/hsts-preload?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/hsts-preload?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/websocket?url=URL</h3><p class="desc">WebSocket support detector — checks for Upgrade headers, scans HTML for ws:// and wss:// URLs, detects Socket.IO, SockJS, and SignalR libraries.</p><pre>curl -s \'http://147.93.131.124/api/websocket?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/websocket?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/dns-propagation?url=URL</h3><p class="desc">DNS propagation checker — queries Google, Cloudflare, OpenDNS, and system default resolvers. Compares A records for consistency and propagation status.</p><pre>curl -s \'http://147.93.131.124/api/dns-propagation?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/dns-propagation?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/permissions-policy?url=URL</h3><p class="desc">Permissions-Policy analyzer — parses Permissions-Policy header, lists directives and restricted features with score.</p><pre>curl -s \'http://147.93.131.124/api/permissions-policy?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/permissions-policy?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/cors-test?url=URL</h3><p class="desc">CORS tester — sends OPTIONS preflight request and inspects Access-Control-Allow-Origin, Methods, Headers, and Credentials.</p><pre>curl -s \'http://147.93.131.124/api/cors-test?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/cors-test?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/waf?url=URL</h3><p class="desc">WAF detector — identifies Web Application Firewalls via header fingerprinting (Cloudflare, AWS, Sucuri, Akamai, Imperva, Fastly, Barracuda).</p><pre>curl -s \'http://147.93.131.124/api/waf?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/waf?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/cache-analysis?url=URL</h3><p class="desc">Cache header analyzer — inspects Cache-Control, ETag, Last-Modified, Expires, Age, and Vary headers with directive parsing and caching score.</p><pre>curl -s \'http://147.93.131.124/api/cache-analysis?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/cache-analysis?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/security-txt?url=URL</h3><p class="desc">Security.txt checker — fetches /.well-known/security.txt and parses Contact, Policy, Encryption, Acknowledgments, Canonical, Preferred-Languages, and Expires fields.</p><pre>curl -s \'http://147.93.131.124/api/security-txt?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/security-txt?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/whois?url=URL</h3><p class="desc">WHOIS lookup — retrieves domain registration info including registrar, creation date, expiry date, name servers, and registrant organization.</p><pre>curl -s \'http://147.93.131.124/api/whois?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/whois?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/content-encoding?url=URL</h3><p class="desc">Content-Encoding analyzer — inspects Content-Encoding, Transfer-Encoding, and Vary headers to detect gzip, brotli, deflate, or zstd compression with scoring.</p><pre>curl -s \'http://147.93.131.124/api/content-encoding?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/content-encoding?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/referrer-policy?url=URL</h3><p class="desc">Referrer-Policy checker — parses the Referrer-Policy header and assesses privacy protection level (high, medium, low, none).</p><pre>curl -s \'http://147.93.131.124/api/referrer-policy?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/referrer-policy?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/x-frame-options?url=URL</h3><p class="desc">X-Frame-Options tester — inspects X-Frame-Options header and CSP frame-ancestors directive for clickjacking protection analysis.</p><pre>curl -s \'http://147.93.131.124/api/x-frame-options?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/x-frame-options?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/subdomains?url=URL</h3><p class="desc">Subdomain enumerator — checks 20 common subdomain prefixes via DNS resolution and returns live subdomains with IP addresses.</p><pre>curl -s \'http://147.93.131.124/api/subdomains?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/subdomains?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/http-methods?url=URL</h3><p class="desc">HTTP method tester — sends OPTIONS request and tests HEAD, PUT, DELETE, PATCH methods. Identifies risky methods enabled on the server.</p><pre>curl -s \'http://147.93.131.124/api/http-methods?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/http-methods?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/server-banner?url=URL</h3><p class="desc">Server banner analyzer — extracts and analyzes the Server response header for version disclosure risks and software identification.</p><pre>curl -s \'http://147.93.131.124/api/server-banner?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/server-banner?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/emails?url=URL</h3><p class="desc">Email harvester — extracts email addresses from page HTML and mailto links. Returns deduplicated email list with count.</p><pre>curl -s \'http://147.93.131.124/api/emails?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/emails?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/open-ports?url=URL</h3><p class="desc">Port scanner lite — tests common HTTP/HTTPS ports (80, 443, 8080, 8443, 3000, 5000, 9090) for TCP connectivity.</p><pre>curl -s \'http://147.93.131.124/api/open-ports?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/open-ports?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/dns-diff?url1=URL1&url2=URL2</h3><p class="desc">DNS record diff — compares A, AAAA, MX, NS, and TXT records between two domains side by side and flags differences.</p><pre>curl -s \'http://147.93.131.124/api/dns-diff?url1=https://example.com&url2=https://google.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/dns-diff?url1=https://example.com&url2=https://google.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/email-obfuscation?url=URL</h3><p class="desc">Email obfuscation detector — scans page HTML for JavaScript-encoded, CSS-hidden, base64, hex-encoded, and HTML entity-encoded email addresses.</p><pre>curl -s \'http://147.93.131.124/api/email-obfuscation?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/email-obfuscation?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/header-timeline?url=URL</h3><p class="desc">Header timeline — fetches a URL twice with 1-second delay and compares response headers to identify dynamic vs stable headers.</p><pre>curl -s \'http://147.93.131.124/api/header-timeline?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/header-timeline?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/domain-age?url=URL</h3><p class="desc">Domain age checker — computes domain age from WHOIS creation date and returns registration timeline in years, months, and days.</p><pre>curl -s \'http://147.93.131.124/api/domain-age?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/domain-age?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/jwt-decode?url=URL</h3><p class="desc">JWT token decoder — scans response headers and body for JWT tokens, decodes header and payload segments, extracts algorithm, issuer, subject, expiry, and issued-at claims.</p><pre>curl -s \'http://147.93.131.124/api/jwt-decode?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/jwt-decode?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/analytics</h3><p class="desc">API usage analytics — returns per-user check counts, top URLs, and usage breakdown by day and week. Requires X-API-Key header.</p><pre>curl -s \'http://147.93.131.124/api/analytics\' -H \'X-API-Key: YOUR_KEY\'</pre></div>'
        + '<div class="ep"><h3><span class="method post">POST</span>/api/webhook-retry</h3><p class="desc">Webhook retry — replays a webhook delivery to a URL with JSON payload and exponential backoff retries on failure.</p><pre>curl -s -X POST \'http://147.93.131.124/api/webhook-retry\' \\\n  -H \'Content-Type: application/json\' \\\n  -d \'{"url":"https://httpbin.org/post","payload":{"test":true}}\'</pre><button class="try-btn" onclick="tryWebhookRetry(this)">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/openapi</h3><p class="desc">OpenAPI 3.0 specification — returns a machine-readable JSON spec listing all 75+ endpoints with parameters and response schemas.</p><pre>curl -s \'http://147.93.131.124/api/openapi\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/openapi\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/rate-limits</h3><p class="desc">Rate limit dashboard — returns per-endpoint rate limit status for authenticated users including tier, limits, and usage counts. Requires X-API-Key header.</p><pre>curl -s \'http://147.93.131.124/api/rate-limits\' -H \'X-API-Key: YOUR_KEY\'</pre></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/geoip?url=URL</h3><p class="desc">IP geolocation — resolves a domain to its IP address and returns geographic location data including country, region, city, coordinates, ISP, and organization.</p><pre>curl -s \'http://147.93.131.124/api/geoip?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/geoip?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/screenshot?url=URL</h3><p class="desc">URL metadata preview — fetches a URL and extracts title, description meta tag, and HTTP status code for quick site previews.</p><pre>curl -s \'http://147.93.131.124/api/screenshot?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/screenshot?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/sitemap-gen?url=URL</h3><p class="desc">Sitemap generator — crawls a page, extracts same-domain links, deduplicates and sorts them, and generates a valid XML sitemap.</p><pre>curl -s \'http://147.93.131.124/api/sitemap-gen?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/sitemap-gen?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/doh?url=URL</h3><p class="desc">DNS over HTTPS lookup — queries Cloudflare DoH resolver for A and AAAA records with TTL values for any domain.</p><pre>curl -s \'http://147.93.131.124/api/doh?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/doh?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/robots-meta?url=URL</h3><p class="desc">Robots meta tag analyzer — extracts and analyzes robots meta tags and X-Robots-Tag headers, reporting index/noindex, follow/nofollow, noarchive, nosnippet, and noimageindex directives.</p><pre>curl -s \'http://147.93.131.124/api/robots-meta?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/robots-meta?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/ssl-chain?url=URL</h3><p class="desc">SSL certificate chain validator — retrieves the full SSL certificate chain from leaf to root, validates chain completeness, and reports subject, issuer, validity dates, and serial for each certificate.</p><pre>curl -s \'http://147.93.131.124/api/ssl-chain?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/ssl-chain?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/header-fingerprint?url=URL</h3><p class="desc">HTTP header fingerprint — generates a unique SHA-256 fingerprint hash from sorted HTTP response header names for server identification and comparison.</p><pre>curl -s \'http://147.93.131.124/api/header-fingerprint?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/header-fingerprint?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/content-type?url=URL</h3><p class="desc">Content-Type sniffer — compares the declared Content-Type response header against the actual body content to detect mismatches between declared and detected types.</p><pre>curl -s \'http://147.93.131.124/api/content-type?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/content-type?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/cookie-security?url=URL</h3><p class="desc">Cookie security audit — parses Set-Cookie headers and evaluates each cookie for security best practices including Secure, HttpOnly, SameSite, Path, and Domain attributes.</p><pre>curl -s \'http://147.93.131.124/api/cookie-security?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/cookie-security?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/dns-caa?url=URL</h3><p class="desc">DNS CAA record checker — queries DNS CAA records for certificate authority authorization, showing which CAs are allowed to issue certificates for the domain.</p><pre>curl -s \'http://147.93.131.124/api/dns-caa?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/dns-caa?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/sri-scan?url=URL</h3><p class="desc">SRI scanner — scans a page for script and stylesheet resources, checking each for Subresource Integrity attributes to detect unprotected external resources.</p><pre>curl -s \'http://147.93.131.124/api/sri-scan?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/sri-scan?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/hsts-analysis?url=URL</h3><p class="desc">HSTS deep analysis — parses the Strict-Transport-Security header to extract max-age, includeSubDomains, and preload directives with compliance scoring.</p><pre>curl -s \'http://147.93.131.124/api/hsts-analysis?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/hsts-analysis?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/dns-mx?url=URL</h3><p class="desc">DNS MX record checker — queries DNS MX records to show email server configuration with priority and exchange fields.</p><pre>curl -s \'http://147.93.131.124/api/dns-mx?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/dns-mx?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/ct-logs?url=URL</h3><p class="desc">CT log checker — queries Certificate Transparency logs via crt.sh for a domain, returning issued certificates with issuer, validity dates, and serial numbers.</p><pre>curl -s \'http://147.93.131.124/api/ct-logs?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/ct-logs?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/http3?url=URL</h3><p class="desc">HTTP/3 detector — checks for Alt-Svc response header to detect HTTP/3 (QUIC) protocol support.</p><pre>curl -s \'http://147.93.131.124/api/http3?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/http3?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/dns-dmarc?url=URL</h3><p class="desc">DMARC record analyzer — queries DNS TXT records for _dmarc subdomain and parses DMARC policy tags including v, p, rua, ruf, sp, adkim, aspf, pct, and fo.</p><pre>curl -s \'http://147.93.131.124/api/dns-dmarc?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/dns-dmarc?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/dns-spf?url=URL</h3><p class="desc">SPF record analyzer — parses DNS SPF records to show email sender authorization mechanisms including include, a, mx, ip4, ip6, all, redirect, exists, and ptr.</p><pre>curl -s \'http://147.93.131.124/api/dns-spf?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/dns-spf?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/dns-ns?url=URL</h3><p class="desc">NS record checker — queries authoritative nameservers for a domain via DNS NS record lookup.</p><pre>curl -s \'http://147.93.131.124/api/dns-ns?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/dns-ns?url=https://example.com\')">Try It</button><div class="result"></div></div>'
        + '<div class="ep"><h3><span class="method get">GET</span>/api/dns-aaaa?url=URL</h3><p class="desc">AAAA record checker — resolves IPv6 AAAA records for a domain to show IPv6 connectivity.</p><pre>curl -s \'http://147.93.131.124/api/dns-aaaa?url=https://example.com\'</pre><button class="try-btn" onclick="tryIt(this,\'/api/dns-aaaa?url=https://example.com\')">Try It</button><div class="result"></div></div>'
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
        + '<script>function tryIt(btn,ep){var r=btn.nextElementSibling;r.style.display="block";r.textContent="Loading...";fetch(ep).then(function(res){return res.json()}).then(function(d){r.textContent=JSON.stringify(d,null,2)}).catch(function(e){r.textContent="Error: "+e.message})}function tryBadge(btn,ep){var r=btn.nextElementSibling;r.style.display="block";r.innerHTML="<img src=\\""+ep+"\\" alt=\\"badge\\"/>"}function tryWebhookRetry(btn){var r=btn.nextElementSibling;r.style.display="block";r.textContent="Loading...";fetch("/api/webhook-retry",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({url:"https://httpbin.org/post",payload:{test:true}})}).then(function(res){return res.json()}).then(function(d){r.textContent=JSON.stringify(d,null,2)}).catch(function(e){r.textContent="Error: "+e.message})}</script>'
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

    // --- OG Image Preview ---
    if (path === '/api/og-image') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'og-image')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const resp = await fetch(normalized, { redirect: 'follow' })
        const html = await resp.text()

        const ogImageMatch = html.match(/<meta[^>]*property\s*=\s*["']og:image["'][^>]*content\s*=\s*["']([^"']*)["']/i)
          || html.match(/<meta[^>]*content\s*=\s*["']([^"']*)["'][^>]*property\s*=\s*["']og:image["']/i)
        const ogTitleMatch = html.match(/<meta[^>]*property\s*=\s*["']og:title["'][^>]*content\s*=\s*["']([^"']*)["']/i)
          || html.match(/<meta[^>]*content\s*=\s*["']([^"']*)["'][^>]*property\s*=\s*["']og:title["']/i)
        const ogDescMatch = html.match(/<meta[^>]*property\s*=\s*["']og:description["'][^>]*content\s*=\s*["']([^"']*)["']/i)
          || html.match(/<meta[^>]*content\s*=\s*["']([^"']*)["'][^>]*property\s*=\s*["']og:description["']/i)
        const ogUrlMatch = html.match(/<meta[^>]*property\s*=\s*["']og:url["'][^>]*content\s*=\s*["']([^"']*)["']/i)
          || html.match(/<meta[^>]*content\s*=\s*["']([^"']*)["'][^>]*property\s*=\s*["']og:url["']/i)
        const ogTypeMatch = html.match(/<meta[^>]*property\s*=\s*["']og:type["'][^>]*content\s*=\s*["']([^"']*)["']/i)
          || html.match(/<meta[^>]*content\s*=\s*["']([^"']*)["'][^>]*property\s*=\s*["']og:type["']/i)
        const ogSiteNameMatch = html.match(/<meta[^>]*property\s*=\s*["']og:site_name["'][^>]*content\s*=\s*["']([^"']*)["']/i)
          || html.match(/<meta[^>]*content\s*=\s*["']([^"']*)["'][^>]*property\s*=\s*["']og:site_name["']/i)

        const ogImage = ogImageMatch ? ogImageMatch[1] : null
        const ogTitle = ogTitleMatch ? ogTitleMatch[1] : null
        const ogDescription = ogDescMatch ? ogDescMatch[1] : null
        const ogUrl = ogUrlMatch ? ogUrlMatch[1] : null
        const ogType = ogTypeMatch ? ogTypeMatch[1] : null
        const ogSiteName = ogSiteNameMatch ? ogSiteNameMatch[1] : null

        return withJson({
          url: normalized,
          og_image: ogImage,
          og_title: ogTitle,
          og_description: ogDescription,
          og_url: ogUrl,
          og_type: ogType,
          og_site_name: ogSiteName,
          has_og_image: !!ogImage,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to fetch OG data'
        return withJson({ error: message }, { status: 502 })
      }
    }

    // --- HTML Validator ---
    if (path === '/api/html-validate') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'html-validate')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const resp = await fetch(normalized, { redirect: 'follow' })
        const html = await resp.text()

        const issues: Array<{ type: string; message: string; severity: string }> = []

        const hasDoctype = /^<!doctype\s+html/i.test(html.trim())
        if (!hasDoctype) {
          issues.push({ type: 'doctype', message: 'Missing <!DOCTYPE html> declaration', severity: 'error' })
        }

        const htmlTagMatch = html.match(/<html\b[^>]*>/i)
        const hasLang = htmlTagMatch ? /\blang\s*=\s*["'][^"']+["']/i.test(htmlTagMatch[0]) : false
        if (!hasLang) {
          issues.push({ type: 'lang', message: 'Missing lang attribute on <html> tag', severity: 'warning' })
        }

        const hasTitleTag = /<title\b[^>]*>[^<]+<\/title>/i.test(html)
        if (!hasTitleTag) {
          issues.push({ type: 'title', message: 'Missing or empty <title> tag', severity: 'error' })
        }

        const hasCharset = /<meta[^>]*charset\s*=/i.test(html)
        if (!hasCharset) {
          issues.push({ type: 'charset', message: 'Missing charset meta tag', severity: 'warning' })
        }

        const hasViewport = /<meta[^>]*name\s*=\s*["']viewport["']/i.test(html)
        if (!hasViewport) {
          issues.push({ type: 'viewport', message: 'Missing viewport meta tag', severity: 'warning' })
        }

        const imgTags = html.match(/<img\b[^>]*>/gi) || []
        let missingAltCount = 0
        for (const img of imgTags) {
          if (!/\balt\s*=/i.test(img)) {
            missingAltCount++
          }
        }
        if (missingAltCount > 0) {
          issues.push({ type: 'alt', message: missingAltCount + ' image(s) missing alt attribute', severity: 'error' })
        }

        const idMatches = html.match(/\bid\s*=\s*["']([^"']+)["']/gi) || []
        const ids: string[] = []
        const duplicateIds: string[] = []
        for (const m of idMatches) {
          const idVal = m.match(/["']([^"']+)["']/)?.[1]
          if (idVal) {
            if (ids.includes(idVal) && !duplicateIds.includes(idVal)) {
              duplicateIds.push(idVal)
            }
            ids.push(idVal)
          }
        }
        if (duplicateIds.length > 0) {
          issues.push({ type: 'duplicate-id', message: 'Duplicate IDs found: ' + duplicateIds.join(', '), severity: 'error' })
        }

        const hasHeadTag = /<head\b/i.test(html)
        if (!hasHeadTag) {
          issues.push({ type: 'head', message: 'Missing <head> section', severity: 'error' })
        }

        const hasBodyTag = /<body\b/i.test(html)
        if (!hasBodyTag) {
          issues.push({ type: 'body', message: 'Missing <body> tag', severity: 'warning' })
        }

        const totalChecks = 8
        const errorCount = issues.filter(i => i.severity === 'error').length
        const warnCount = issues.filter(i => i.severity === 'warning').length
        const score = Math.max(0, Math.round(100 - (errorCount * 12.5) - (warnCount * 6.25)))

        return withJson({
          url: normalized,
          issues,
          issue_count: issues.length,
          errors: errorCount,
          warnings: warnCount,
          has_doctype: hasDoctype,
          has_lang: hasLang,
          has_title: hasTitleTag,
          has_charset: hasCharset,
          has_viewport: hasViewport,
          score,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to validate HTML'
        return withJson({ error: message }, { status: 502 })
      }
    }

    // --- Favicon Checker ---
    if (path === '/api/favicon') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'favicon')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const resp = await fetch(normalized, { redirect: 'follow' })
        const html = await resp.text()
        const baseUrl = new URL(normalized)

        const favicons: Array<{ href: string; rel: string; type: string | null; sizes: string | null }> = []

        const linkTags = html.match(/<link\b[^>]*>/gi) || []
        for (const tag of linkTags) {
          const relMatch = tag.match(/\brel\s*=\s*["']([^"']*)["']/i)
          if (!relMatch) continue
          const rel = relMatch[1].toLowerCase()
          if (rel !== 'icon' && rel !== 'shortcut icon' && rel !== 'apple-touch-icon' && rel !== 'apple-touch-icon-precomposed') continue

          const hrefMatch = tag.match(/\bhref\s*=\s*["']([^"']*)["']/i)
          if (!hrefMatch) continue
          const href = hrefMatch[1]

          const typeMatch = tag.match(/\btype\s*=\s*["']([^"']*)["']/i)
          const sizesMatch = tag.match(/\bsizes\s*=\s*["']([^"']*)["']/i)

          let resolvedHref = href
          try {
            resolvedHref = new URL(href, baseUrl.origin).toString()
          } catch {}

          favicons.push({
            href: resolvedHref,
            rel,
            type: typeMatch ? typeMatch[1] : null,
            sizes: sizesMatch ? sizesMatch[1] : null,
          })
        }

        // Check default /favicon.ico if no favicons found in HTML
        let hasDefaultFavicon = false
        if (favicons.length === 0) {
          try {
            const icoResp = await fetch(baseUrl.origin + '/favicon.ico', { method: 'HEAD', redirect: 'follow' })
            if (icoResp.ok) {
              hasDefaultFavicon = true
              favicons.push({
                href: baseUrl.origin + '/favicon.ico',
                rel: 'icon',
                type: 'image/x-icon',
                sizes: null,
              })
            }
          } catch {}
        }

        return withJson({
          url: normalized,
          favicons,
          favicon_count: favicons.length,
          has_favicon: favicons.length > 0,
          has_default_favicon_ico: hasDefaultFavicon || favicons.some(f => f.href.endsWith('/favicon.ico')),
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to check favicons'
        return withJson({ error: message }, { status: 502 })
      }
    }

    // --- Lighthouse Audit ---
    if (path === '/api/lighthouse') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'lighthouse')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const start = performance.now()
        const resp = await fetch(normalized, { redirect: 'follow' })
        const elapsed = performance.now() - start
        const html = await resp.text()
        const sizeKb = new TextEncoder().encode(html).length / 1024

        // Performance score (TTFB + size based)
        let perfScore = 100
        if (elapsed > 3000) perfScore -= 40
        else if (elapsed > 1500) perfScore -= 25
        else if (elapsed > 500) perfScore -= 10
        if (sizeKb > 500) perfScore -= 20
        else if (sizeKb > 200) perfScore -= 10
        if (!resp.headers.get('content-encoding')) perfScore -= 10
        perfScore = Math.max(0, Math.min(100, perfScore))

        // Accessibility score
        let a11yScore = 100
        const imgsNoAlt = (html.match(/<img\b(?![^>]*\balt\s*=)[^>]*>/gi) || []).length
        if (imgsNoAlt > 0) a11yScore -= Math.min(30, imgsNoAlt * 5)
        if (!/<html[^>]*\blang\s*=/i.test(html)) a11yScore -= 15
        if (!/<h1[\s>]/i.test(html)) a11yScore -= 10
        if (!/<main[\s>]/i.test(html)) a11yScore -= 10
        if (!/<nav[\s>]/i.test(html)) a11yScore -= 5
        a11yScore = Math.max(0, Math.min(100, a11yScore))

        // SEO score
        let seoScore = 100
        if (!/<title[^>]*>[^<]+<\/title>/i.test(html)) seoScore -= 25
        if (!/<meta[^>]*name\s*=\s*["']description["'][^>]*>/i.test(html)) seoScore -= 20
        if (!/<h1[\s>]/i.test(html)) seoScore -= 15
        if (!/<meta[^>]*property\s*=\s*["']og:title["'][^>]*>/i.test(html)) seoScore -= 10
        if (!/<link[^>]*rel\s*=\s*["']canonical["'][^>]*>/i.test(html)) seoScore -= 10
        seoScore = Math.max(0, Math.min(100, seoScore))

        // Security score (from headers)
        let secScore = 0
        const secHeaders = ['strict-transport-security', 'x-content-type-options', 'x-frame-options', 'content-security-policy', 'referrer-policy', 'permissions-policy', 'x-xss-protection', 'cross-origin-opener-policy', 'cross-origin-resource-policy', 'cross-origin-embedder-policy']
        for (const h of secHeaders) {
          if (resp.headers.get(h)) secScore += 10
        }

        const overall = Math.round(perfScore * 0.25 + a11yScore * 0.25 + seoScore * 0.25 + secScore * 0.25)
        let grade = 'F'
        if (overall >= 90) grade = 'A'
        else if (overall >= 80) grade = 'B'
        else if (overall >= 70) grade = 'C'
        else if (overall >= 60) grade = 'D'

        return withJson({
          url: normalized,
          performance: perfScore,
          accessibility: a11yScore,
          seo: seoScore,
          security: secScore,
          overall,
          grade,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to run lighthouse audit'
        return withJson({ error: message }, { status: 502 })
      }
    }

    // --- CSP Analyzer ---
    if (path === '/api/csp') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'csp')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const resp = await fetch(normalized, { redirect: 'follow' })
        const cspHeader = resp.headers.get('content-security-policy') || ''
        const hasCsp = cspHeader.length > 0

        const directives: Array<{ name: string; value: string }> = []
        let hasUnsafeInline = false
        let hasUnsafeEval = false

        if (hasCsp) {
          const parts = cspHeader.split(';').map(s => s.trim()).filter(Boolean)
          for (const part of parts) {
            const spaceIdx = part.indexOf(' ')
            const name = spaceIdx > 0 ? part.substring(0, spaceIdx) : part
            const value = spaceIdx > 0 ? part.substring(spaceIdx + 1).trim() : ''
            directives.push({ name, value })
            if (value.includes("'unsafe-inline'")) hasUnsafeInline = true
            if (value.includes("'unsafe-eval'")) hasUnsafeEval = true
          }
        }

        let score = 0
        if (hasCsp) {
          score += 30
          const directiveNames = directives.map(d => d.name)
          if (directiveNames.includes('default-src')) score += 15
          if (directiveNames.includes('script-src')) score += 15
          if (directiveNames.includes('style-src')) score += 10
          if (directiveNames.includes('img-src')) score += 5
          if (directiveNames.includes('object-src')) score += 5
          if (directiveNames.includes('frame-src') || directiveNames.includes('frame-ancestors')) score += 5
          if (!hasUnsafeInline) score += 10
          if (!hasUnsafeEval) score += 5
        }
        score = Math.min(100, score)

        return withJson({
          url: normalized,
          has_csp: hasCsp,
          raw_header: hasCsp ? cspHeader : null,
          directives,
          directive_count: directives.length,
          has_unsafe_inline: hasUnsafeInline,
          has_unsafe_eval: hasUnsafeEval,
          score,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to analyze CSP'
        return withJson({ error: message }, { status: 502 })
      }
    }

    // --- Response Headers Inspector ---
    if (path === '/api/response-headers') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'response-headers')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const resp = await fetch(normalized, { redirect: 'follow' })

        const securityNames = ['strict-transport-security', 'x-content-type-options', 'x-frame-options', 'content-security-policy', 'referrer-policy', 'permissions-policy', 'x-xss-protection', 'cross-origin-opener-policy', 'cross-origin-resource-policy', 'cross-origin-embedder-policy']
        const cachingNames = ['cache-control', 'expires', 'etag', 'last-modified', 'age', 'vary']
        const corsNames = ['access-control-allow-origin', 'access-control-allow-methods', 'access-control-allow-headers', 'access-control-expose-headers', 'access-control-max-age']
        const serverNames = ['server', 'x-powered-by', 'via', 'x-request-id', 'x-runtime']

        const headers: Record<string, { value: string; category: string }> = {}
        const securityHeaders: string[] = []
        const cachingHeaders: string[] = []

        resp.headers.forEach((value, name) => {
          const lower = name.toLowerCase()
          let category = 'custom'
          if (securityNames.includes(lower)) { category = 'security'; securityHeaders.push(lower) }
          else if (cachingNames.includes(lower)) { category = 'caching'; cachingHeaders.push(lower) }
          else if (corsNames.includes(lower)) category = 'cors'
          else if (serverNames.includes(lower)) category = 'server'
          else if (lower.startsWith('content-')) category = 'content'
          headers[name] = { value, category }
        })

        return withJson({
          url: normalized,
          headers,
          header_count: Object.keys(headers).length,
          security_headers: securityHeaders,
          caching_headers: cachingHeaders,
          status_code: resp.status,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to inspect headers'
        return withJson({ error: message }, { status: 502 })
      }
    }

    // --- Subresource Integrity Checker ---
    if (path === '/api/sri') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'sri')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const resp = await fetch(normalized, { redirect: 'follow' })
        const html = await resp.text()

        const scriptRegex = /<script\b([^>]*)>/gi
        const linkRegex = /<link\b([^>]*rel\s*=\s*["']stylesheet["'][^>]*)>/gi

        const scripts: Array<{ src: string | null; has_integrity: boolean; integrity: string | null }> = []
        let scriptMatch
        while ((scriptMatch = scriptRegex.exec(html)) !== null) {
          const attrs = scriptMatch[1]
          const srcMatch = attrs.match(/src\s*=\s*["']([^"']+)["']/)
          if (!srcMatch) continue
          const integrityMatch = attrs.match(/integrity\s*=\s*["']([^"']+)["']/)
          scripts.push({
            src: srcMatch[1],
            has_integrity: !!integrityMatch,
            integrity: integrityMatch ? integrityMatch[1] : null,
          })
        }

        const stylesheets: Array<{ href: string | null; has_integrity: boolean; integrity: string | null }> = []
        let linkMatch
        while ((linkMatch = linkRegex.exec(html)) !== null) {
          const attrs = linkMatch[1]
          const hrefMatch = attrs.match(/href\s*=\s*["']([^"']+)["']/)
          if (!hrefMatch) continue
          const integrityMatch = attrs.match(/integrity\s*=\s*["']([^"']+)["']/)
          stylesheets.push({
            href: hrefMatch[1],
            has_integrity: !!integrityMatch,
            integrity: integrityMatch ? integrityMatch[1] : null,
          })
        }

        const scriptsWithSri = scripts.filter(s => s.has_integrity).length
        const scriptsWithoutSri = scripts.filter(s => !s.has_integrity).length
        const stylesheetsWithSri = stylesheets.filter(s => s.has_integrity).length
        const stylesheetsWithoutSri = stylesheets.filter(s => !s.has_integrity).length
        const total = scripts.length + stylesheets.length
        const withSri = scriptsWithSri + stylesheetsWithSri
        const score = total === 0 ? 100 : Math.round((withSri / total) * 100)

        return withJson({
          url: normalized,
          scripts,
          stylesheets,
          scripts_with_sri: scriptsWithSri,
          scripts_without_sri: scriptsWithoutSri,
          stylesheets_with_sri: stylesheetsWithSri,
          stylesheets_without_sri: stylesheetsWithoutSri,
          total_resources: total,
          score,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to check SRI'
        return withJson({ error: message }, { status: 502 })
      }
    }

    // --- Cookie Consent Detector ---
    if (path === '/api/cookie-consent') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'cookie-consent')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const resp = await fetch(normalized, { redirect: 'follow' })
        const html = await resp.text()
        const lower = html.toLowerCase()

        const platforms: Array<{ name: string; pattern: string }> = [
          { name: 'OneTrust', pattern: 'onetrust' },
          { name: 'CookieBot', pattern: 'cookiebot' },
          { name: 'CookieYes', pattern: 'cookieyes' },
          { name: 'Osano', pattern: 'osano' },
          { name: 'TrustArc', pattern: 'trustarc' },
          { name: 'Quantcast', pattern: 'quantcast' },
          { name: 'Didomi', pattern: 'didomi' },
          { name: 'Iubenda', pattern: 'iubenda' },
          { name: 'Termly', pattern: 'termly' },
          { name: 'CookieConsent', pattern: 'cookieconsent' },
        ]

        const indicators: string[] = []
        let detectedPlatform: string | null = null

        for (const p of platforms) {
          if (lower.includes(p.pattern)) {
            indicators.push(p.name + ' script/reference detected')
            if (!detectedPlatform) detectedPlatform = p.name
          }
        }

        const bannerPatterns = ['cookie-consent', 'cookie-banner', 'cookie-notice', 'cookie-popup', 'cookie-modal', 'cookie-bar', 'gdpr-banner', 'gdpr-consent', 'consent-banner', 'consent-modal', 'cc-banner', 'cc-window']
        for (const bp of bannerPatterns) {
          if (lower.includes(bp)) {
            indicators.push('HTML contains "' + bp + '" class/id')
          }
        }

        const gdprSignals: string[] = []
        if (lower.includes('gdpr')) gdprSignals.push('GDPR reference found in page')
        if (lower.includes('cookie policy')) gdprSignals.push('Cookie policy reference found')
        if (lower.includes('privacy policy')) gdprSignals.push('Privacy policy reference found')
        if (lower.includes('manage cookies')) gdprSignals.push('Manage cookies option found')
        if (lower.includes('accept cookies') || lower.includes('accept all')) gdprSignals.push('Accept cookies button text found')
        if (lower.includes('reject cookies') || lower.includes('reject all')) gdprSignals.push('Reject cookies option found')

        const hasConsentBanner = indicators.length > 0 || gdprSignals.length > 0
        const score = Math.min(100, indicators.length * 25 + gdprSignals.length * 15)

        return withJson({
          url: normalized,
          has_consent_banner: hasConsentBanner,
          detected_platform: detectedPlatform,
          indicators,
          gdpr_signals: gdprSignals,
          score,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to detect cookie consent'
        return withJson({ error: message }, { status: 502 })
      }
    }

    // --- TLS Cipher Suite Analyzer ---
    if (path === '/api/tls-ciphers') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'tls-ciphers')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const hostname = new URL(normalized).hostname

        const result = await new Promise<{ protocol: string; cipher: string; bits: number }>((resolve, reject) => {
          const socket = tls.connect({ host: hostname, port: 443, servername: hostname, rejectUnauthorized: false }, () => {
            const cipher = socket.getCipher()
            const protocol = socket.getProtocol() || 'unknown'
            socket.destroy()
            resolve({
              protocol,
              cipher: cipher ? cipher.name : 'unknown',
              bits: cipher ? (cipher as any).bits || 0 : 0,
            })
          })
          socket.on('error', (err) => {
            socket.destroy()
            reject(err)
          })
          socket.setTimeout(10000, () => {
            socket.destroy()
            reject(new Error('TLS connection timeout'))
          })
        })

        const weakCiphers = ['RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT']
        const warnings: string[] = []
        for (const w of weakCiphers) {
          if (result.cipher.toUpperCase().includes(w)) {
            warnings.push('Weak cipher component detected: ' + w)
          }
        }
        if (result.protocol === 'TLSv1' || result.protocol === 'TLSv1.1') {
          warnings.push('Deprecated TLS protocol: ' + result.protocol)
        }

        const isSecure = warnings.length === 0 && (result.protocol === 'TLSv1.2' || result.protocol === 'TLSv1.3')

        return withJson({
          url: normalized,
          hostname,
          protocol: result.protocol,
          cipher: result.cipher,
          cipher_bits: result.bits,
          is_secure: isSecure,
          warnings,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to analyze TLS ciphers'
        return withJson({ error: message }, { status: 502 })
      }
    }

    // --- HSTS Preload Checker ---
    if (path === '/api/hsts-preload') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'hsts-preload')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const resp = await fetch(normalized, { redirect: 'follow' })
        const hstsHeader = resp.headers.get('strict-transport-security') || ''

        const hasHsts = hstsHeader.length > 0
        const maxAgeMatch = hstsHeader.match(/max-age\s*=\s*(\d+)/i)
        const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0
        const includeSubDomains = /includeSubDomains/i.test(hstsHeader)
        const preload = /preload/i.test(hstsHeader)
        const isHttps = normalized.startsWith('https://')

        const warnings: string[] = []
        if (!hasHsts) warnings.push('No Strict-Transport-Security header found')
        if (hasHsts && maxAge < 31536000) warnings.push('max-age must be at least 31536000 (1 year) for preload')
        if (hasHsts && !includeSubDomains) warnings.push('includeSubDomains directive is required for preload')
        if (hasHsts && !preload) warnings.push('preload directive is missing')
        if (!isHttps) warnings.push('Site must be served over HTTPS for preload')

        const preloadReady = hasHsts && maxAge >= 31536000 && includeSubDomains && preload && isHttps
        let score = 0
        if (hasHsts) score += 25
        if (maxAge >= 31536000) score += 25
        if (includeSubDomains) score += 25
        if (preload) score += 25

        return withJson({
          url: normalized,
          has_hsts: hasHsts,
          raw_header: hstsHeader || null,
          max_age: maxAge,
          include_sub_domains: includeSubDomains,
          preload,
          preload_ready: preloadReady,
          warnings,
          score,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to check HSTS'
        return withJson({ error: message }, { status: 502 })
      }
    }

    // --- WebSocket Support Detector ---
    if (path === '/api/websocket') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'websocket')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const resp = await fetch(normalized, { redirect: 'follow' })
        const html = await resp.text()

        const upgradeHeader = resp.headers.get('upgrade') || ''
        const connectionHeader = resp.headers.get('connection') || ''
        const hasWebsocketHeaders = /websocket/i.test(upgradeHeader) || /upgrade/i.test(connectionHeader)

        const wsUrlMatches = html.match(/wss?:\/\/[^\s"'<>]+/gi) || []
        const wsUrls = [...new Set(wsUrlMatches)]

        const socketIoDetected = /socket\.io/i.test(html) || /io\(\s*['"]wss?:/i.test(html)
        const sockjsDetected = /sockjs/i.test(html)
        const signalrDetected = /signalr/i.test(html)

        const libraries: string[] = []
        if (socketIoDetected) libraries.push('Socket.IO')
        if (sockjsDetected) libraries.push('SockJS')
        if (signalrDetected) libraries.push('SignalR')

        let score = 0
        if (hasWebsocketHeaders) score += 40
        if (wsUrls.length > 0) score += 40
        if (libraries.length > 0) score += 20

        return withJson({
          url: normalized,
          has_websocket_headers: hasWebsocketHeaders,
          upgrade_header: upgradeHeader || null,
          ws_urls_found: wsUrls,
          socket_io_detected: socketIoDetected,
          sockjs_detected: sockjsDetected,
          signalr_detected: signalrDetected,
          libraries_detected: libraries,
          score,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to detect WebSocket support'
        return withJson({ error: message }, { status: 502 })
      }
    }

    // --- DNS Propagation Checker ---
    if (path === '/api/dns-propagation') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'dns-propagation')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const hostname = new URL(normalized).hostname
        const resolverConfigs = [
          { name: 'Google', ip: '8.8.8.8' },
          { name: 'Cloudflare', ip: '1.1.1.1' },
          { name: 'OpenDNS', ip: '208.67.222.222' },
        ]

        const results: Array<{ name: string; ip: string; records: string[]; error?: string }> = []

        try {
          const records = await dnsResolve(hostname, 'A')
          results.push({ name: 'System Default', ip: 'system', records: records as string[] })
        } catch (e) {
          results.push({ name: 'System Default', ip: 'system', records: [], error: e instanceof Error ? e.message : 'resolve failed' })
        }

        for (const cfg of resolverConfigs) {
          try {
            const resolver = new Resolver()
            resolver.setServers([cfg.ip])
            const records = await resolver.resolve(hostname, 'A')
            results.push({ name: cfg.name, ip: cfg.ip, records: records as string[] })
          } catch (e) {
            results.push({ name: cfg.name, ip: cfg.ip, records: [], error: e instanceof Error ? e.message : 'resolve failed' })
          }
        }

        const recordSets = results.filter(r => r.records.length > 0).map(r => JSON.stringify([...r.records].sort()))
        const uniqueSets = [...new Set(recordSets)]
        const consistent = uniqueSets.length <= 1
        const propagationComplete = consistent && results.every(r => r.records.length > 0)

        return withJson({
          url: normalized,
          hostname,
          resolvers: results,
          consistent,
          propagation_complete: propagationComplete,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to check DNS propagation'
        return withJson({ error: message }, { status: 502 })
      }
    }

    if (path === '/api/permissions-policy') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'permissions-policy')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const resp = await fetch(normalized, { redirect: 'follow' })
        const raw = resp.headers.get('permissions-policy') || resp.headers.get('feature-policy') || null
        const directives: Array<{ feature: string; allowlist: string }> = []
        const restrictedFeatures: string[] = []

        if (raw) {
          const parts = raw.split(',')
          for (const part of parts) {
            const trimmed = part.trim()
            const eqIdx = trimmed.indexOf('=')
            if (eqIdx !== -1) {
              const feature = trimmed.slice(0, eqIdx).trim()
              const allowlist = trimmed.slice(eqIdx + 1).trim()
              directives.push({ feature, allowlist })
              if (allowlist === '()' || allowlist === 'none') {
                restrictedFeatures.push(feature)
              }
            }
          }
        }

        const score = raw ? Math.min(100, directives.length * 10) : 0

        return withJson({
          url: normalized,
          has_policy: !!raw,
          raw_header: raw,
          directives,
          restricted_features: restrictedFeatures,
          score,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to check permissions policy'
        return withJson({ error: message }, { status: 502 })
      }
    }

    if (path === '/api/cors-test') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'cors-test')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const resp = await fetch(normalized, {
          method: 'OPTIONS',
          headers: { 'Origin': 'https://example.com', 'Access-Control-Request-Method': 'GET' },
        })
        const acao = resp.headers.get('access-control-allow-origin')
        const acam = resp.headers.get('access-control-allow-methods')
        const acah = resp.headers.get('access-control-allow-headers')
        const acma = resp.headers.get('access-control-max-age')
        const acac = resp.headers.get('access-control-allow-credentials')

        const allowsAllOrigins = acao === '*'
        const allowedMethods = acam ? acam.split(',').map(m => m.trim()).filter(Boolean) : []
        const allowedHeaders = acah ? acah.split(',').map(h => h.trim()).filter(Boolean) : []
        const maxAge = acma ? parseInt(acma, 10) : null
        const credentialsAllowed = acac === 'true'

        let score = 0
        if (acao) score += 25
        if (acam) score += 25
        if (acah) score += 25
        if (!allowsAllOrigins && acao) score += 25

        return withJson({
          url: normalized,
          allows_all_origins: allowsAllOrigins,
          allowed_origins: acao,
          allowed_methods: allowedMethods,
          allowed_headers: allowedHeaders,
          max_age: maxAge,
          credentials_allowed: credentialsAllowed,
          score,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to test CORS'
        return withJson({ error: message }, { status: 502 })
      }
    }

    if (path === '/api/waf') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'waf')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const resp = await fetch(normalized, { redirect: 'follow' })
        const indicators: string[] = []
        let provider: string | null = null

        const cfRay = resp.headers.get('cf-ray')
        const server = (resp.headers.get('server') || '').toLowerCase()
        const xPoweredBy = (resp.headers.get('x-powered-by') || '').toLowerCase()
        const via = (resp.headers.get('via') || '').toLowerCase()

        if (cfRay) { indicators.push('cf-ray header present'); provider = 'Cloudflare' }
        if (server.includes('cloudflare')) { indicators.push('server: cloudflare'); provider = provider || 'Cloudflare' }
        if (resp.headers.get('x-sucuri-id')) { indicators.push('x-sucuri-id header present'); provider = provider || 'Sucuri' }
        if (resp.headers.get('x-akamai-transformed')) { indicators.push('x-akamai-transformed header present'); provider = provider || 'Akamai' }
        if (server.includes('akamai')) { indicators.push('server contains akamai'); provider = provider || 'Akamai' }
        if (resp.headers.get('x-cdn') === 'Incapsula') { indicators.push('x-cdn: Incapsula'); provider = provider || 'Imperva/Incapsula' }
        if (resp.headers.get('x-iinfo')) { indicators.push('x-iinfo header present'); provider = provider || 'Imperva/Incapsula' }
        if (server.includes('awselb') || resp.headers.get('x-amzn-requestid')) { indicators.push('AWS load balancer detected'); provider = provider || 'AWS WAF' }
        if (resp.headers.get('x-amz-cf-id')) { indicators.push('x-amz-cf-id header present'); provider = provider || 'AWS CloudFront' }
        if (server.includes('barracuda')) { indicators.push('server contains barracuda'); provider = provider || 'Barracuda' }
        if (via.includes('varnish')) { indicators.push('via contains varnish'); provider = provider || 'Varnish' }
        if (resp.headers.get('x-fastly-request-id')) { indicators.push('x-fastly-request-id header present'); provider = provider || 'Fastly' }

        const wafDetected = indicators.length > 0
        const score = wafDetected ? Math.min(100, indicators.length * 50) : 0

        return withJson({
          url: normalized,
          waf_detected: wafDetected,
          provider,
          indicators,
          score,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to detect WAF'
        return withJson({ error: message }, { status: 502 })
      }
    }

    if (path === '/api/cache-analysis') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'cache-analysis')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const resp = await fetch(normalized, { redirect: 'follow' })

        const cacheControl = resp.headers.get('cache-control')
        const etag = resp.headers.get('etag')
        const lastModified = resp.headers.get('last-modified')
        const expires = resp.headers.get('expires')
        const age = resp.headers.get('age')
        const vary = resp.headers.get('vary')
        const pragma = resp.headers.get('pragma')

        const directives: string[] = []
        if (cacheControl) {
          for (const part of cacheControl.split(',')) {
            directives.push(part.trim())
          }
        }

        let score = 0
        if (cacheControl) score += 30
        if (etag) score += 20
        if (lastModified) score += 15
        if (directives.some(d => d.startsWith('max-age'))) score += 15
        if (vary) score += 10
        if (!directives.includes('no-store')) score += 10

        return withJson({
          url: normalized,
          cache_control: cacheControl,
          directives,
          etag,
          last_modified: lastModified,
          expires,
          age: age ? parseInt(age, 10) : null,
          vary,
          pragma,
          score,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to analyze cache headers'
        return withJson({ error: message }, { status: 502 })
      }
    }

    if (path === '/api/security-txt') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'security-txt')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const base = new URL(normalized).origin
        const securityTxtUrl = base + '/.well-known/security.txt'
        const resp = await fetch(securityTxtUrl, { redirect: 'follow' })
        const contentType = (resp.headers.get('content-type') || '').toLowerCase()
        const body = await resp.text()

        const hasSecurityTxt = resp.status === 200 && (contentType.includes('text/plain') || body.includes('Contact:'))

        const fields: Array<{ key: string; value: string }> = []
        let contact: string | null = null
        let policy: string | null = null
        let encryption: string | null = null
        let acknowledgments: string | null = null
        let canonical: string | null = null
        let preferredLanguages: string | null = null
        let expiresField: string | null = null

        if (hasSecurityTxt) {
          for (const line of body.split('\n')) {
            const trimmed = line.trim()
            if (trimmed.startsWith('#') || !trimmed.includes(':')) continue
            const colonIdx = trimmed.indexOf(':')
            const key = trimmed.slice(0, colonIdx).trim()
            const value = trimmed.slice(colonIdx + 1).trim()
            if (!key || !value) continue
            fields.push({ key, value })
            const keyLower = key.toLowerCase()
            if (keyLower === 'contact' && !contact) contact = value
            if (keyLower === 'policy' && !policy) policy = value
            if (keyLower === 'encryption' && !encryption) encryption = value
            if (keyLower === 'acknowledgments' && !acknowledgments) acknowledgments = value
            if (keyLower === 'canonical' && !canonical) canonical = value
            if (keyLower === 'preferred-languages' && !preferredLanguages) preferredLanguages = value
            if (keyLower === 'expires' && !expiresField) expiresField = value
          }
        }

        let score = 0
        if (hasSecurityTxt) score += 25
        if (contact) score += 25
        if (policy) score += 20
        if (encryption) score += 15
        if (expiresField) score += 15

        return withJson({
          url: normalized,
          has_security_txt: hasSecurityTxt,
          security_txt_url: securityTxtUrl,
          fields,
          contact,
          policy,
          encryption,
          acknowledgments,
          canonical,
          preferred_languages: preferredLanguages,
          expires: expiresField,
          score,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to check security.txt'
        return withJson({ error: message }, { status: 502 })
      }
    }

    if (path === '/api/whois') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'whois')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const domain = new URL(normalized).hostname.replace(/^www\./, '')

        const proc = Bun.spawn(['whois', domain], { stdout: 'pipe', stderr: 'pipe' })
        const output = await new Response(proc.stdout).text()
        await proc.exited

        let registrar: string | null = null
        let created: string | null = null
        let expires: string | null = null
        let updated: string | null = null
        let registrantOrg: string | null = null
        const nameServers: string[] = []

        for (const line of output.split('\n')) {
          const trimmed = line.trim()
          const lower = trimmed.toLowerCase()
          if (!registrar && (lower.startsWith('registrar:') || lower.startsWith('registrar name:'))) {
            registrar = trimmed.split(':').slice(1).join(':').trim()
          }
          if (!created && (lower.startsWith('creation date:') || lower.startsWith('created:') || lower.startsWith('created on:'))) {
            created = trimmed.split(':').slice(1).join(':').trim()
          }
          if (!expires && (lower.startsWith('registry expiry date:') || lower.startsWith('expiration date:') || lower.startsWith('expires:') || lower.startsWith('expires on:'))) {
            expires = trimmed.split(':').slice(1).join(':').trim()
          }
          if (!updated && (lower.startsWith('updated date:') || lower.startsWith('last updated:'))) {
            updated = trimmed.split(':').slice(1).join(':').trim()
          }
          if (!registrantOrg && (lower.startsWith('registrant organization:') || lower.startsWith('registrant:'))) {
            registrantOrg = trimmed.split(':').slice(1).join(':').trim()
          }
          if (lower.startsWith('name server:') || lower.startsWith('nserver:')) {
            const ns = trimmed.split(':').slice(1).join(':').trim().toLowerCase()
            if (ns && !nameServers.includes(ns)) nameServers.push(ns)
          }
        }

        let score = 0
        if (registrar) score += 25
        if (created) score += 25
        if (expires) score += 25
        if (nameServers.length > 0) score += 25

        return withJson({
          url: normalized,
          domain,
          registrar,
          created,
          expires,
          updated,
          registrant_organization: registrantOrg,
          name_servers: nameServers,
          score,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to perform WHOIS lookup'
        return withJson({ error: message }, { status: 502 })
      }
    }

    if (path === '/api/content-encoding') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'content-encoding')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const resp = await fetch(normalized, { redirect: 'follow' })
        const body = await resp.text()
        const contentEncoding = resp.headers.get('content-encoding')
        const transferEncoding = resp.headers.get('transfer-encoding')
        const vary = resp.headers.get('vary')
        const contentLength = resp.headers.get('content-length')

        let compressionType = 'none'
        if (contentEncoding) {
          const ce = contentEncoding.toLowerCase()
          if (ce.includes('br')) compressionType = 'brotli'
          else if (ce.includes('gzip')) compressionType = 'gzip'
          else if (ce.includes('deflate')) compressionType = 'deflate'
          else if (ce.includes('zstd')) compressionType = 'zstd'
          else compressionType = ce
        }

        const compressed = compressionType !== 'none'
        const bodySize = body.length
        const clSize = contentLength ? parseInt(contentLength, 10) : null

        let score = 0
        if (compressed) score += 60
        if (vary && vary.toLowerCase().includes('accept-encoding')) score += 20
        if (contentEncoding) score += 20

        return withJson({
          url: normalized,
          content_encoding: contentEncoding,
          transfer_encoding: transferEncoding,
          vary,
          compression_type: compressionType,
          compressed,
          content_length: clSize,
          body_size: bodySize,
          score,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to analyze content encoding'
        return withJson({ error: message }, { status: 502 })
      }
    }

    if (path === '/api/referrer-policy') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'referrer-policy')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const resp = await fetch(normalized, { redirect: 'follow' })
        const policy = resp.headers.get('referrer-policy')
        const hasPolicy = !!policy

        const policyScores: Record<string, number> = {
          'no-referrer': 100,
          'strict-origin-when-cross-origin': 100,
          'same-origin': 90,
          'strict-origin': 85,
          'origin': 70,
          'origin-when-cross-origin': 60,
          'no-referrer-when-downgrade': 40,
          'unsafe-url': 10,
        }

        const privacyLevels: Record<string, string> = {
          'no-referrer': 'high',
          'strict-origin-when-cross-origin': 'high',
          'same-origin': 'high',
          'strict-origin': 'medium',
          'origin': 'medium',
          'origin-when-cross-origin': 'medium',
          'no-referrer-when-downgrade': 'low',
          'unsafe-url': 'none',
        }

        const policyLower = policy ? policy.toLowerCase().trim() : ''
        const score = hasPolicy ? (policyScores[policyLower] || 50) : 25
        const privacyLevel = hasPolicy ? (privacyLevels[policyLower] || 'medium') : 'unknown'

        return withJson({
          url: normalized,
          has_policy: hasPolicy,
          policy: policy || null,
          privacy_level: privacyLevel,
          score,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to check referrer policy'
        return withJson({ error: message }, { status: 502 })
      }
    }

    if (path === '/api/x-frame-options') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'x-frame-options')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const resp = await fetch(normalized, { redirect: 'follow' })
        const xfo = resp.headers.get('x-frame-options')
        const csp = resp.headers.get('content-security-policy')

        const hasXfo = !!xfo
        let xfoValue = xfo ? xfo.toUpperCase().trim() : null

        let hasFrameAncestors = false
        let cspFrameAncestors: string | null = null
        if (csp) {
          const faMatch = csp.match(/frame-ancestors\s+([^;]+)/i)
          if (faMatch) {
            hasFrameAncestors = true
            cspFrameAncestors = faMatch[1].trim()
          }
        }

        let protectionLevel = 'none'
        let score = 0

        if (hasFrameAncestors && hasXfo) {
          protectionLevel = 'strong'
          score = 100
        } else if (hasFrameAncestors) {
          protectionLevel = 'good'
          score = 85
        } else if (hasXfo) {
          if (xfoValue === 'DENY') {
            protectionLevel = 'strong'
            score = 90
          } else if (xfoValue === 'SAMEORIGIN') {
            protectionLevel = 'medium'
            score = 60
          } else {
            protectionLevel = 'weak'
            score = 30
          }
        }

        return withJson({
          url: normalized,
          x_frame_options: xfo,
          has_xfo: hasXfo,
          has_frame_ancestors: hasFrameAncestors,
          csp_frame_ancestors: cspFrameAncestors,
          protection_level: protectionLevel,
          score,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to check X-Frame-Options'
        return withJson({ error: message }, { status: 502 })
      }
    }

    if (path === '/api/subdomains') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'subdomains')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const domain = new URL(normalized).hostname
        const prefixes = ['www', 'mail', 'ftp', 'admin', 'blog', 'api', 'dev', 'staging', 'test', 'app', 'cdn', 'shop', 'store', 'portal', 'support', 'docs', 'status', 'm', 'mobile', 'secure']
        const found: Array<{ subdomain: string; ip: string }> = []

        const resolver = new Resolver()
        for (const prefix of prefixes) {
          const sub = prefix + '.' + domain
          try {
            const ips = await resolver.resolve4(sub)
            if (ips.length > 0) {
              found.push({ subdomain: sub, ip: ips[0] })
            }
          } catch {}
        }

        const score = found.length === 0 ? 0 : Math.min(100, found.length * 10)

        return withJson({
          url: normalized,
          domain,
          subdomains_checked: prefixes.length,
          subdomains_found: found,
          count: found.length,
          score,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to enumerate subdomains'
        return withJson({ error: message }, { status: 502 })
      }
    }

    if (path === '/api/http-methods') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'http-methods')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)

        let allowHeader: string | null = null
        try {
          const optResp = await fetch(normalized, { method: 'OPTIONS', redirect: 'follow' })
          allowHeader = optResp.headers.get('allow')
        } catch {}

        const methodsToTest = ['HEAD', 'PUT', 'DELETE', 'PATCH']
        const methodsTested: Record<string, number> = {}

        for (const m of methodsToTest) {
          try {
            const resp = await fetch(normalized, { method: m, redirect: 'follow' })
            methodsTested[m] = resp.status
          } catch {
            methodsTested[m] = 0
          }
        }

        const riskyMethods: string[] = []
        const risky = ['PUT', 'DELETE', 'PATCH', 'TRACE', 'CONNECT']
        for (const m of risky) {
          const code = methodsTested[m]
          if (code && code >= 200 && code < 300) {
            riskyMethods.push(m)
          }
        }

        if (allowHeader) {
          const allowed = allowHeader.split(',').map(s => s.trim().toUpperCase())
          for (const m of risky) {
            if (allowed.includes(m) && !riskyMethods.includes(m)) {
              riskyMethods.push(m)
            }
          }
        }

        let score = 100
        score -= riskyMethods.length * 20

        return withJson({
          url: normalized,
          allow_header: allowHeader,
          methods_tested: methodsTested,
          risky_methods: riskyMethods,
          score: Math.max(0, score),
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to test HTTP methods'
        return withJson({ error: message }, { status: 502 })
      }
    }

    if (path === '/api/server-banner') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'server-banner')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const resp = await fetch(normalized, { redirect: 'follow' })
        const serverHeader = resp.headers.get('server')
        const xPoweredBy = resp.headers.get('x-powered-by')

        const hasServerHeader = !!serverHeader
        let serverSoftware: string | null = null
        let versionDisclosed = false
        let riskLevel = 'none'
        let score = 100

        if (serverHeader) {
          const versionMatch = serverHeader.match(/[\d]+\.[\d]+/)
          const osMatch = serverHeader.match(/(Ubuntu|Debian|CentOS|Red Hat|Windows|Unix|Linux)/i)

          const parts = serverHeader.split(/[\s\/]/)
          serverSoftware = parts[0] || serverHeader

          if (osMatch && versionMatch) {
            versionDisclosed = true
            riskLevel = 'critical'
            score = 10
          } else if (versionMatch) {
            versionDisclosed = true
            riskLevel = 'medium'
            score = 40
          } else {
            riskLevel = 'low'
            score = 80
          }
        }

        return withJson({
          url: normalized,
          server_header: serverHeader,
          has_server_header: hasServerHeader,
          x_powered_by: xPoweredBy,
          server_software: serverSoftware,
          version_disclosed: versionDisclosed,
          risk_level: riskLevel,
          score,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to analyze server banner'
        return withJson({ error: message }, { status: 502 })
      }
    }

    if (path === '/api/emails') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'emails')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const resp = await fetch(normalized, { redirect: 'follow' })
        const html = await resp.text()

        const emailRegex = /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g
        const bodyEmails = html.match(emailRegex) || []

        const mailtoRegex = /href\s*=\s*["']mailto:([^"'?]+)/gi
        const mailtoEmails: string[] = []
        let m: RegExpExecArray | null
        while ((m = mailtoRegex.exec(html)) !== null) {
          mailtoEmails.push(m[1])
        }

        const allEmails = [...new Set([...bodyEmails, ...mailtoEmails])]

        let score = 0
        if (allEmails.length > 0) score = 50
        if (allEmails.length >= 3) score = 75
        if (allEmails.length >= 10) score = 100

        return withJson({
          url: normalized,
          emails_found: allEmails,
          count: allEmails.length,
          source: 'html+mailto',
          score,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to extract emails'
        return withJson({ error: message }, { status: 502 })
      }
    }

    if (path === '/api/open-ports') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'open-ports')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const hostname = new URL(normalized).hostname
        const portsToCheck = [80, 443, 8080, 8443, 3000, 5000, 9090]
        const openPorts: Array<{ port: number; status: string }> = []
        const closedPorts: number[] = []

        for (const port of portsToCheck) {
          try {
            await new Promise<void>((resolve, reject) => {
              const net = require('node:net')
              const sock = net.createConnection({ host: hostname, port, timeout: 3000 }, () => {
                sock.destroy()
                resolve()
              })
              sock.on('timeout', () => { sock.destroy(); reject(new Error('timeout')) })
              sock.on('error', (err: Error) => { reject(err) })
            })
            openPorts.push({ port, status: 'open' })
          } catch {
            closedPorts.push(port)
          }
        }

        let score = 0
        if (openPorts.length > 0) score = Math.min(100, openPorts.length * 35)

        return withJson({
          url: normalized,
          host: hostname,
          ports_checked: portsToCheck.length,
          open_ports: openPorts,
          closed_ports: closedPorts,
          score,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to scan ports'
        return withJson({ error: message }, { status: 502 })
      }
    }

    if (path === '/api/dns-diff') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target1 = url.searchParams.get('url1')
      const target2 = url.searchParams.get('url2')
      if (!target1 || !target2) {
        return withJson({ error: 'url1 and url2 parameters required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'dns-diff')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized1 = normalizeUrl(target1)
        const normalized2 = normalizeUrl(target2)
        const domain1 = new URL(normalized1).hostname
        const domain2 = new URL(normalized2).hostname

        const resolver = new Resolver()
        const recordTypes = ['A', 'AAAA', 'MX', 'NS', 'TXT'] as const
        const records: Record<string, { domain1: any; domain2: any; match: boolean }> = {}
        let matching = 0

        for (const rtype of recordTypes) {
          let r1: any = []
          let r2: any = []
          try { r1 = await resolver.resolve(domain1, rtype) } catch {}
          try { r2 = await resolver.resolve(domain2, rtype) } catch {}

          const s1 = JSON.stringify(Array.isArray(r1) ? r1.sort() : r1)
          const s2 = JSON.stringify(Array.isArray(r2) ? r2.sort() : r2)
          const match = s1 === s2
          if (match) matching++

          records[rtype] = { domain1: r1, domain2: r2, match }
        }

        const total = recordTypes.length
        const score = Math.round((matching / total) * 100)

        return withJson({
          domain1,
          domain2,
          records,
          total_record_types: total,
          matching,
          score,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to compare DNS records'
        return withJson({ error: message }, { status: 502 })
      }
    }

    // --- Email Obfuscation Detector ---
    if (path === '/api/email-obfuscation') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'email-obfuscation')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const resp = await fetch(normalized, { redirect: 'follow', headers: { 'User-Agent': 'PulseBot/1.0' } })
        const html = await resp.text()

        const techniques: Array<{ technique: string; evidence: string }> = []

        // JavaScript-encoded emails: String.fromCharCode patterns
        const charCodeMatches = html.match(/String\.fromCharCode\s*\([0-9,\s]+\)/gi) || []
        for (const m of charCodeMatches) {
          try {
            const nums = m.match(/\d+/g)?.map(Number) || []
            const decoded = String.fromCharCode(...nums)
            if (decoded.includes('@')) {
              techniques.push({ technique: 'javascript_charcode', evidence: decoded.trim() })
            }
          } catch {}
        }

        // Base64-encoded emails: atob('...') patterns
        const atobMatches = html.match(/atob\s*\(\s*['"][A-Za-z0-9+/=]+['"]\s*\)/gi) || []
        for (const m of atobMatches) {
          try {
            const b64 = m.match(/['"]([A-Za-z0-9+/=]+)['"]/)?.[1]
            if (b64) {
              const decoded = atob(b64)
              if (decoded.includes('@')) {
                techniques.push({ technique: 'javascript_base64', evidence: decoded.trim() })
              }
            }
          } catch {}
        }

        // Hex-encoded strings containing @
        const hexMatches = html.match(/\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){3,}/g) || []
        for (const m of hexMatches) {
          try {
            const decoded = m.replace(/\\x([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
            if (decoded.includes('@')) {
              techniques.push({ technique: 'hex_encoded', evidence: decoded.trim() })
            }
          } catch {}
        }

        // CSS-hidden emails: display:none or visibility:hidden near @ symbols
        const hiddenBlocks = html.match(/<[^>]+(display\s*:\s*none|visibility\s*:\s*hidden)[^>]*>[^<]*@[^<]*<\/[^>]+>/gi) || []
        for (const m of hiddenBlocks) {
          const emailMatch = m.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/)?.[0]
          if (emailMatch) {
            techniques.push({ technique: 'css_hidden', evidence: emailMatch })
          }
        }

        // HTML entity-encoded emails: &#64; for @ , &#46; for .
        const entityPattern = /[a-zA-Z0-9._%+-]*(?:&#(?:64|x40);)[a-zA-Z0-9._%+-]*(?:&#(?:46|x2[eE]);)[a-zA-Z]{2,}/g
        const entityMatches = html.match(entityPattern) || []
        for (const m of entityMatches) {
          const decoded = m.replace(/&#(\d+);/g, (_, n) => String.fromCharCode(parseInt(n)))
            .replace(/&#x([0-9a-fA-F]+);/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
          techniques.push({ technique: 'html_entity_encoded', evidence: decoded })
        }

        // data-email or data-user/data-domain attributes
        const dataEmailMatches = html.match(/data-email\s*=\s*["'][^"']+["']/gi) || []
        for (const m of dataEmailMatches) {
          const val = m.match(/["']([^"']+)["']/)?.[1]
          if (val) techniques.push({ technique: 'data_attribute', evidence: val })
        }

        const count = techniques.length
        const hasObfuscation = count > 0
        const score = hasObfuscation ? Math.min(count * 25, 100) : 0

        return withJson({
          url: normalized,
          techniques_found: techniques,
          count,
          has_obfuscation: hasObfuscation,
          score,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to detect email obfuscation'
        return withJson({ error: message }, { status: 502 })
      }
    }

    // --- Header Timeline ---
    if (path === '/api/header-timeline') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'header-timeline')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)

        const resp1 = await fetch(normalized, { redirect: 'follow', headers: { 'User-Agent': 'PulseBot/1.0' } })
        const headers1: Record<string, string> = {}
        resp1.headers.forEach((v, k) => { headers1[k] = v })

        await new Promise(resolve => setTimeout(resolve, 1000))

        const resp2 = await fetch(normalized, { redirect: 'follow', headers: { 'User-Agent': 'PulseBot/1.0' } })
        const headers2: Record<string, string> = {}
        resp2.headers.forEach((v, k) => { headers2[k] = v })

        const allKeys = new Set([...Object.keys(headers1), ...Object.keys(headers2)])
        const changedHeaders: string[] = []
        const stableHeaders: string[] = []

        for (const key of allKeys) {
          if (headers1[key] !== headers2[key]) {
            changedHeaders.push(key)
          } else {
            stableHeaders.push(key)
          }
        }

        const total = allKeys.size
        const stableCount = stableHeaders.length
        const stabilityScore = total > 0 ? Math.round((stableCount / total) * 100) : 100

        return withJson({
          url: normalized,
          fetch_count: 2,
          headers_first: headers1,
          headers_second: headers2,
          changed_headers: changedHeaders.sort(),
          stable_headers: stableHeaders.sort(),
          stability_score: stabilityScore,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to track header timeline'
        return withJson({ error: message }, { status: 502 })
      }
    }

    // --- Domain Age Checker ---
    if (path === '/api/domain-age') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'domain-age')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const domain = new URL(normalized).hostname

        const proc = Bun.spawn(['whois', domain], { stdout: 'pipe', stderr: 'pipe' })
        const output = await new Response(proc.stdout).text()
        await proc.exited

        let creationDate: string | null = null
        let registrar: string | null = null
        let expiryDate: string | null = null

        for (const line of output.split('\n')) {
          const lower = line.toLowerCase().trim()
          if (!creationDate && (lower.startsWith('creation date:') || lower.startsWith('created:') || lower.startsWith('created on:') || lower.startsWith('registration date:') || lower.startsWith('registered on:'))) {
            creationDate = line.split(':').slice(1).join(':').trim()
          }
          if (!registrar && (lower.startsWith('registrar:') || lower.startsWith('registrar name:'))) {
            registrar = line.split(':').slice(1).join(':').trim()
          }
          if (!expiryDate && (lower.startsWith('registry expiry date:') || lower.startsWith('expiry date:') || lower.startsWith('expires:') || lower.startsWith('expires on:') || lower.startsWith('paid-till:'))) {
            expiryDate = line.split(':').slice(1).join(':').trim()
          }
        }

        if (!creationDate) {
          return withJson({
            url: normalized,
            domain,
            creation_date: null,
            expiry_date: expiryDate || null,
            age_years: null,
            age_months: null,
            age_days: null,
            registrar: registrar || null,
            score: 0,
            error: 'Could not parse creation date from WHOIS',
          })
        }

        const created = new Date(creationDate)
        const now = new Date()
        const diffMs = now.getTime() - created.getTime()
        const ageDays = Math.floor(diffMs / (1000 * 60 * 60 * 24))
        const ageMonths = Math.floor(ageDays / 30.44)
        const ageYears = Math.floor(ageDays / 365.25)

        // Score: older domains are more trustworthy
        let score = 0
        if (ageYears >= 10) score = 100
        else if (ageYears >= 5) score = 80
        else if (ageYears >= 2) score = 60
        else if (ageYears >= 1) score = 40
        else score = 20

        return withJson({
          url: normalized,
          domain,
          creation_date: created.toISOString().slice(0, 10),
          expiry_date: expiryDate || null,
          age_years: ageYears,
          age_months: ageMonths,
          age_days: ageDays,
          registrar: registrar || null,
          score,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to check domain age'
        return withJson({ error: message }, { status: 502 })
      }
    }

    // --- JWT Token Decoder ---
    if (path === '/api/jwt-decode') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'jwt-decode')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const resp = await fetch(normalized, { redirect: 'follow' })
        const headers = headerObject(resp.headers)
        const body = await resp.text()

        const jwtPattern = /[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g
        const tokensFound: Array<{ source: string; header: Record<string, unknown>; payload: Record<string, unknown>; algorithm: string | null; issuer: string | null; subject: string | null; expiry: string | null; issued_at: string | null }> = []

        const decodeBase64Url = (s: string): string => {
          const padded = s.replace(/-/g, '+').replace(/_/g, '/') + '=='.slice(0, (4 - (s.length % 4)) % 4)
          try { return atob(padded) } catch { return '{}' }
        }

        const tryParseJwt = (token: string, source: string) => {
          const parts = token.split('.')
          if (parts.length !== 3) return
          try {
            const header = JSON.parse(decodeBase64Url(parts[0]))
            const payload = JSON.parse(decodeBase64Url(parts[1]))
            tokensFound.push({
              source,
              header,
              payload,
              algorithm: header.alg || null,
              issuer: payload.iss || null,
              subject: payload.sub || null,
              expiry: payload.exp ? new Date(payload.exp * 1000).toISOString() : null,
              issued_at: payload.iat ? new Date(payload.iat * 1000).toISOString() : null,
            })
          } catch {}
        }

        // Check response headers for JWTs
        for (const [hName, hValue] of Object.entries(headers)) {
          const matches = hValue.match(jwtPattern)
          if (matches) {
            for (const m of matches) tryParseJwt(m, 'header:' + hName)
          }
        }

        // Check response body for JWTs
        const bodyMatches = body.match(jwtPattern)
        if (bodyMatches) {
          for (const m of bodyMatches) tryParseJwt(m, 'body')
        }

        return withJson({
          url: normalized,
          tokens_found: tokensFound,
          count: tokensFound.length,
          has_jwt: tokensFound.length > 0,
          score: tokensFound.length > 0 ? 100 : 0,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to decode JWT'
        return withJson({ error: message }, { status: 502 })
      }
    }

    // --- API Usage Analytics ---
    if (path === '/api/analytics') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim()
      if (!apiKey) {
        return withJson({ error: 'X-API-Key header required' }, { status: 401 })
      }

      const keyRow = getApiKeyByKey(apiKey)
      if (!keyRow) {
        return withJson({ error: 'Invalid API key' }, { status: 401 })
      }

      try {
        const totalChecks = db.prepare('SELECT COUNT(*) as count FROM checks WHERE api_key = ?').get(apiKey) as { count: number } | null
        const topUrls = db.prepare('SELECT url, COUNT(*) as count FROM checks WHERE api_key = ? GROUP BY url ORDER BY count DESC LIMIT 10').all(apiKey) as Array<{ url: string; count: number }>

        const todayStr = utcDateKey()
        const checksToday = db.prepare('SELECT COUNT(*) as count FROM checks WHERE api_key = ? AND created_at >= ?').get(apiKey, todayStr + 'T00:00:00.000Z') as { count: number } | null

        const weekAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString()
        const checksThisWeek = db.prepare('SELECT COUNT(*) as count FROM checks WHERE api_key = ? AND created_at >= ?').get(apiKey, weekAgo) as { count: number } | null

        return withJson({
          api_key: apiKey.slice(0, 8) + '...',
          total_checks: totalChecks?.count || 0,
          top_urls: topUrls,
          checks_today: checksToday?.count || 0,
          checks_this_week: checksThisWeek?.count || 0,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to fetch analytics'
        return withJson({ error: message }, { status: 500 })
      }
    }

    // --- Webhook Retry ---
    if (path === '/api/webhook-retry') {
      if (request.method !== 'POST') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'webhook-retry')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const body = await request.json() as { url?: string; payload?: unknown }
        if (!body.url) {
          return withJson({ error: 'url field required in JSON body' }, { status: 400 })
        }

        const webhookUrl = body.url
        const payload = body.payload || {}
        const maxRetries = 3
        let lastStatus = 0
        let lastTime = 0
        let success = false
        let retries = 0

        for (let attempt = 0; attempt <= maxRetries; attempt++) {
          if (attempt > 0) {
            // Exponential backoff: 1s, 2s, 4s
            await new Promise(r => setTimeout(r, Math.pow(2, attempt - 1) * 1000))
          }

          const start = performance.now()
          try {
            const resp = await fetch(webhookUrl, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(payload),
            })
            lastTime = Math.round(performance.now() - start)
            lastStatus = resp.status

            if (resp.status >= 200 && resp.status < 300) {
              success = true
              retries = attempt
              break
            }
          } catch {
            lastTime = Math.round(performance.now() - start)
            lastStatus = 0
          }
          retries = attempt
        }

        return withJson({
          url: webhookUrl,
          status_code: lastStatus,
          response_time_ms: lastTime,
          success,
          retries,
          max_retries: maxRetries,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to retry webhook'
        return withJson({ error: message }, { status: 400 })
      }
    }

    // --- OpenAPI 3.0 Specification ---
    if (path === '/api/openapi') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const spec = {
        openapi: '3.0.0',
        info: {
          title: 'Pulse API',
          version: '1.0.0',
          description: 'Site intelligence API providing 75+ endpoints for website health, security, performance, and SEO analysis.',
        },
        servers: [{ url: 'http://147.93.131.124', description: 'Production' }],
        paths: {} as Record<string, any>,
      }

      const addPath = (p: string, method: string, summary: string, params: Array<{ name: string; in_: string; required: boolean; schema: { type: string } }> = [], auth: boolean = false) => {
        if (!spec.paths[p]) spec.paths[p] = {}
        const op: any = { summary, responses: { '200': { description: 'Success' } } }
        if (params.length > 0) {
          op.parameters = params.map(x => ({ name: x.name, in: x.in_, required: x.required, schema: { type: x.schema.type } }))
        }
        if (auth) {
          op.parameters = op.parameters || []
          op.parameters.push({ name: 'X-API-Key', in: 'header', required: true, schema: { type: 'string' } })
        }
        spec.paths[p][method] = op
      }

      const urlParam = { name: 'url', in_: 'query', required: true, schema: { type: 'string' } }
      const optKey = { name: 'X-API-Key', in_: 'header', required: false, schema: { type: 'string' } }

      // Pages
      addPath('/', 'get', 'Landing page')
      addPath('/status', 'get', 'Public status page')
      addPath('/dashboard', 'get', 'Account dashboard')
      addPath('/docs', 'get', 'Interactive API documentation')

      // Core API
      addPath('/api/health', 'get', 'Health check')
      addPath('/api/check', 'get', 'URL analysis', [urlParam, optKey])
      addPath('/api/dns', 'get', 'DNS record analysis', [urlParam, optKey])
      addPath('/api/perf', 'get', 'Performance scoring', [urlParam, optKey])
      addPath('/api/seo', 'get', 'SEO audit', [urlParam, optKey])
      addPath('/api/compare', 'get', 'Side-by-side URL comparison', [urlParam, { name: 'url2', in_: 'query', required: true, schema: { type: 'string' } }, optKey])
      addPath('/api/headers', 'get', 'Security headers audit', [urlParam, optKey])
      addPath('/api/tech', 'get', 'Technology stack detection', [urlParam, optKey])
      addPath('/api/score', 'get', 'Aggregate site quality score', [urlParam, optKey])
      addPath('/api/sitemap', 'get', 'XML sitemap parser', [urlParam, optKey])
      addPath('/api/ssl', 'get', 'SSL certificate monitor', [urlParam, optKey])
      addPath('/api/robots', 'get', 'Robots.txt parser', [urlParam, optKey])
      addPath('/api/mixed-content', 'get', 'Mixed content scanner', [urlParam, optKey])
      addPath('/api/timeline', 'get', 'Redirect chain timeline', [urlParam, optKey])
      addPath('/api/accessibility', 'get', 'WCAG accessibility audit', [urlParam, optKey])
      addPath('/api/cookies', 'get', 'Cookie scanner', [urlParam, optKey])
      addPath('/api/weight', 'get', 'Page weight analyzer', [urlParam, optKey])
      addPath('/api/carbon', 'get', 'Carbon footprint estimator', [urlParam, optKey])
      addPath('/api/links', 'get', 'Link checker', [urlParam, optKey])
      addPath('/api/meta', 'get', 'Meta tag validator', [urlParam, optKey])
      addPath('/api/http2', 'get', 'HTTP/2 checker', [urlParam, optKey])
      addPath('/api/structured-data', 'get', 'Structured data validator', [urlParam, optKey])
      addPath('/api/dnsbl', 'get', 'DNS blacklist lookup', [urlParam, optKey])
      addPath('/api/og-image', 'get', 'Open Graph image preview', [urlParam, optKey])
      addPath('/api/html-validate', 'get', 'HTML validator', [urlParam, optKey])
      addPath('/api/favicon', 'get', 'Favicon checker', [urlParam, optKey])
      addPath('/api/lighthouse', 'get', 'Lighthouse audit', [urlParam, optKey])
      addPath('/api/csp', 'get', 'CSP analyzer', [urlParam, optKey])
      addPath('/api/response-headers', 'get', 'Response headers inspector', [urlParam, optKey])
      addPath('/api/sri', 'get', 'SRI checker', [urlParam, optKey])
      addPath('/api/cookie-consent', 'get', 'Cookie consent detector', [urlParam, optKey])
      addPath('/api/tls-ciphers', 'get', 'TLS cipher suite analyzer', [urlParam, optKey])
      addPath('/api/hsts-preload', 'get', 'HSTS preload checker', [urlParam, optKey])
      addPath('/api/websocket', 'get', 'WebSocket support detector', [urlParam, optKey])
      addPath('/api/dns-propagation', 'get', 'DNS propagation checker', [urlParam, optKey])
      addPath('/api/permissions-policy', 'get', 'Permissions-Policy analyzer', [urlParam, optKey])
      addPath('/api/cors-test', 'get', 'CORS tester', [urlParam, optKey])
      addPath('/api/waf', 'get', 'WAF detector', [urlParam, optKey])
      addPath('/api/cache-analysis', 'get', 'Cache header analyzer', [urlParam, optKey])
      addPath('/api/security-txt', 'get', 'Security.txt checker', [urlParam, optKey])
      addPath('/api/whois', 'get', 'WHOIS lookup', [urlParam, optKey])
      addPath('/api/content-encoding', 'get', 'Content-Encoding analyzer', [urlParam, optKey])
      addPath('/api/referrer-policy', 'get', 'Referrer-Policy checker', [urlParam, optKey])
      addPath('/api/x-frame-options', 'get', 'X-Frame-Options tester', [urlParam, optKey])
      addPath('/api/subdomains', 'get', 'Subdomain enumerator', [urlParam, optKey])
      addPath('/api/http-methods', 'get', 'HTTP method tester', [urlParam, optKey])
      addPath('/api/server-banner', 'get', 'Server banner analyzer', [urlParam, optKey])
      addPath('/api/emails', 'get', 'Email address harvester', [urlParam, optKey])
      addPath('/api/open-ports', 'get', 'Port scanner lite', [urlParam, optKey])
      addPath('/api/dns-diff', 'get', 'DNS record diff', [urlParam, { name: 'url2', in_: 'query', required: true, schema: { type: 'string' } }, optKey])
      addPath('/api/email-obfuscation', 'get', 'Email obfuscation detector', [urlParam, optKey])
      addPath('/api/header-timeline', 'get', 'Header timeline tracker', [urlParam, optKey])
      addPath('/api/domain-age', 'get', 'Domain age checker', [urlParam, optKey])
      addPath('/api/jwt-decode', 'get', 'JWT token decoder', [urlParam, optKey])
      addPath('/api/analytics', 'get', 'API usage analytics', [], true)
      addPath('/api/webhook-retry', 'post', 'Webhook retry with exponential backoff')
      addPath('/api/uptime', 'get', 'Global uptime statistics')
      addPath('/api/test-webhook', 'post', 'Webhook delivery test')
      addPath('/api/batch', 'post', 'Bulk URL analysis')
      addPath('/api/badge/{id}', 'get', 'Uptime SVG badge', [{ name: 'id', in_: 'path', required: true, schema: { type: 'integer' } }])
      addPath('/api/register', 'post', 'Register email for API key')
      addPath('/api/history', 'get', 'Last 50 checks', [], true)
      addPath('/api/account', 'get', 'User account info', [], true)
      addPath('/api/subscribe', 'post', 'Create Stripe checkout session')
      addPath('/api/webhooks/stripe', 'post', 'Handle Stripe webhooks')
      addPath('/api/monitors', 'get', 'List active monitors', [], true)
      addPath('/api/monitors', 'post', 'Create scheduled URL monitor', [], true)
      addPath('/api/monitors/{id}', 'delete', 'Delete a monitor', [{ name: 'id', in_: 'path', required: true, schema: { type: 'integer' } }], true)
      addPath('/api/monitors/{id}/checks', 'get', 'Get monitor checks', [{ name: 'id', in_: 'path', required: true, schema: { type: 'integer' } }], true)
      // New Sprint 25 endpoints
      addPath('/api/openapi', 'get', 'OpenAPI 3.0 specification')
      addPath('/api/rate-limits', 'get', 'Rate limit status for authenticated user', [], true)
      addPath('/api/geoip', 'get', 'IP geolocation lookup', [urlParam, optKey])
      addPath('/api/screenshot', 'get', 'URL metadata preview', [urlParam, optKey])
      addPath('/api/sitemap-gen', 'get', 'Sitemap generator', [urlParam, optKey])
      addPath('/api/doh', 'get', 'DNS over HTTPS lookup', [urlParam, optKey])
      addPath('/api/robots-meta', 'get', 'Robots meta tag analyzer', [urlParam, optKey])
      addPath('/api/ssl-chain', 'get', 'SSL certificate chain validator', [urlParam, optKey])
      addPath('/api/header-fingerprint', 'get', 'HTTP header fingerprint', [urlParam, optKey])
      addPath('/api/content-type', 'get', 'Content-Type sniffer', [urlParam, optKey])
      addPath('/api/cookie-security', 'get', 'Cookie security audit', [urlParam, optKey])
      addPath('/api/dns-caa', 'get', 'DNS CAA record checker', [urlParam, optKey])
      addPath('/api/sri-scan', 'get', 'Subresource Integrity scanner', [urlParam, optKey])
      addPath('/api/hsts-analysis', 'get', 'HSTS deep analysis', [urlParam, optKey])
      addPath('/api/dns-mx', 'get', 'DNS MX record checker', [urlParam, optKey])
      addPath('/api/ct-logs', 'get', 'Certificate Transparency log checker', [urlParam, optKey])
      addPath('/api/http3', 'get', 'HTTP/3 Alt-Svc detector', [urlParam, optKey])
      addPath('/api/dns-dmarc', 'get', 'DMARC record analyzer', [urlParam, optKey])
      addPath('/api/dns-spf', 'get', 'SPF record analyzer', [urlParam, optKey])
      addPath('/api/dns-ns', 'get', 'NS record checker', [urlParam, optKey])
      addPath('/api/dns-aaaa', 'get', 'AAAA record checker', [urlParam, optKey])

      return withJson(spec)
    }

    // --- Rate Limit Dashboard ---
    if (path === '/api/rate-limits') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim()
      if (!apiKey) {
        return withJson({ error: 'X-API-Key header required' }, { status: 401 })
      }

      const keyRow = getApiKeyByKey(apiKey)
      if (!keyRow) {
        return withJson({ error: 'Invalid API key' }, { status: 401 })
      }

      try {
        const tier = keyRow.tier === 'pro' ? 'pro' : 'free'
        const limits: Record<string, number> = { anon: 5, free: 50, pro: 500 }
        const today = utcDateKey()

        const rows = db.prepare('SELECT endpoint, checks_today, last_reset FROM endpoint_rate_limits WHERE key = ?').all(apiKey) as Array<{ endpoint: string; checks_today: number; last_reset: string }>

        const endpoints = rows
          .filter(r => r.last_reset === today)
          .map(r => ({ endpoint: r.endpoint, checks_today: r.checks_today, limit: limits[tier] || 50 }))

        return withJson({
          api_key: apiKey.slice(0, 8) + '...',
          tier,
          limits,
          endpoints,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to fetch rate limits'
        return withJson({ error: message }, { status: 500 })
      }
    }

    // --- IP Geolocation ---
    if (path === '/api/geoip') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'geoip')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const hostname = new URL(normalized).hostname
        const addresses = await dnsResolve(hostname)
        const ip = addresses[0] || hostname

        const geoResp = await fetch('http://ip-api.com/json/' + ip + '?fields=status,message,country,regionName,city,lat,lon,isp,org')
        const geo = (await geoResp.json()) as any

        if (geo.status === 'fail') {
          return withJson({ error: geo.message || 'Geolocation lookup failed', ip }, { status: 502 })
        }

        return withJson({
          url: normalized,
          ip,
          country: geo.country || null,
          region: geo.regionName || null,
          city: geo.city || null,
          lat: geo.lat || null,
          lon: geo.lon || null,
          isp: geo.isp || null,
          org: geo.org || null,
          score: 100,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to resolve IP geolocation'
        return withJson({ error: message }, { status: 502 })
      }
    }

    // --- URL Screenshot (Metadata Preview) ---
    if (path === '/api/screenshot') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'screenshot')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const resp = await fetch(normalized, { redirect: 'follow', signal: AbortSignal.timeout(10000) })
        const html = await resp.text()
        const statusCode = resp.status

        const titleMatch = html.match(/<title[^>]*>([^<]*)<\/title>/i)
        const title = titleMatch ? titleMatch[1].trim() : null

        const descMatch = html.match(/<meta[^>]+name=["']description["'][^>]+content=["']([^"']*)["']/i)
          || html.match(/<meta[^>]+content=["']([^"']*)["'][^>]+name=["']description["']/i)
        const description = descMatch ? descMatch[1].trim() : null

        return withJson({
          url: normalized,
          title,
          description,
          status_code: statusCode,
          screenshot_available: false,
          note: 'Metadata preview mode',
          score: 100,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to fetch URL metadata'
        return withJson({ error: message }, { status: 502 })
      }
    }

    // --- Sitemap Generator ---
    if (path === '/api/sitemap-gen') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'sitemap-gen')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const baseUrl = new URL(normalized)
        const baseHostname = baseUrl.hostname

        const resp = await fetch(normalized, { redirect: 'follow', signal: AbortSignal.timeout(10000) })
        const html = await resp.text()

        const linkRegex = /<a[^>]+href=["']([^"'#]+)["']/gi
        const seen = new Set<string>()
        let match: RegExpExecArray | null
        while ((match = linkRegex.exec(html)) !== null) {
          try {
            const href = match[1].trim()
            let absolute: URL
            if (href.startsWith('http://') || href.startsWith('https://')) {
              absolute = new URL(href)
            } else if (href.startsWith('/')) {
              absolute = new URL(href, normalized)
            } else {
              continue
            }
            if (absolute.hostname === baseHostname) {
              seen.add(absolute.origin + absolute.pathname)
            }
          } catch {}
        }

        const links = Array.from(seen).sort()
        const sitemapEntries = links.map(l => '  <url><loc>' + l + '</loc></url>').join('\n')
        const sitemapXml = '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n' + sitemapEntries + '\n</urlset>'

        return withJson({
          url: normalized,
          pages_found: links.length,
          sitemap_xml: sitemapXml,
          links,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to generate sitemap'
        return withJson({ error: message }, { status: 502 })
      }
    }

    // --- DNS over HTTPS ---
    if (path === '/api/doh') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'doh')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const hostname = new URL(normalized).hostname

        const [aResp, aaaaResp] = await Promise.all([
          fetch('https://cloudflare-dns.com/dns-query?name=' + hostname + '&type=A', { headers: { Accept: 'application/dns-json' }, signal: AbortSignal.timeout(10000) }),
          fetch('https://cloudflare-dns.com/dns-query?name=' + hostname + '&type=AAAA', { headers: { Accept: 'application/dns-json' }, signal: AbortSignal.timeout(10000) }),
        ])

        const aData = (await aResp.json()) as any
        const aaaaData = (await aaaaResp.json()) as any

        const aRecords = (aData.Answer || []).filter((r: any) => r.type === 1).map((r: any) => r.data)
        const aaaaRecords = (aaaaData.Answer || []).filter((r: any) => r.type === 28).map((r: any) => r.data)
        const ttl = (aData.Answer && aData.Answer[0]?.TTL) || (aaaaData.Answer && aaaaData.Answer[0]?.TTL) || 0

        return withJson({
          url: normalized,
          domain: hostname,
          resolver: 'cloudflare',
          records: {
            A: aRecords,
            AAAA: aaaaRecords,
          },
          ttl,
          score: 100,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to perform DNS over HTTPS lookup'
        return withJson({ error: message }, { status: 502 })
      }
    }

    // --- Robots Meta Tag Analyzer ---
    if (path === '/api/robots-meta') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'robots-meta')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const resp = await fetch(normalized, { signal: AbortSignal.timeout(10000), redirect: 'follow' })
        const html = await resp.text()
        const xRobotsTag = resp.headers.get('x-robots-tag') || null

        const metaTags: Array<{ name: string; content: string }> = []
        const metaRegex1 = /<meta\s+[^>]*name\s*=\s*["'](robots|googlebot)["'][^>]*content\s*=\s*["']([^"']*)["'][^>]*\/?>/gi
        const metaRegex2 = /<meta\s+[^>]*content\s*=\s*["']([^"']*)["'][^>]*name\s*=\s*["'](robots|googlebot)["'][^>]*\/?>/gi
        let match: RegExpExecArray | null
        while ((match = metaRegex1.exec(html)) !== null) {
          metaTags.push({ name: match[1].toLowerCase(), content: match[2] })
        }
        while ((match = metaRegex2.exec(html)) !== null) {
          metaTags.push({ name: match[2].toLowerCase(), content: match[1] })
        }

        const allDirectives = metaTags.map(t => t.content).join(', ').toLowerCase()
        const xDirectives = xRobotsTag ? xRobotsTag.toLowerCase() : ''
        const combined = allDirectives + ', ' + xDirectives

        const directives = {
          index: !combined.includes('noindex'),
          follow: !combined.includes('nofollow'),
          noarchive: combined.includes('noarchive'),
          nosnippet: combined.includes('nosnippet'),
          noimageindex: combined.includes('noimageindex'),
        }

        let score = 100
        if (!directives.index) score -= 30
        if (!directives.follow) score -= 30
        if (directives.noarchive) score -= 10
        if (directives.nosnippet) score -= 10
        if (directives.noimageindex) score -= 10

        return withJson({
          url: normalized,
          meta_tags: metaTags,
          x_robots_tag: xRobotsTag,
          directives,
          score: Math.max(0, score),
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to analyze robots meta tags'
        return withJson({ error: message }, { status: 502 })
      }
    }

    // --- SSL Certificate Chain Validator ---
    if (path === '/api/ssl-chain') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'ssl-chain')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const hostname = new URL(normalized).hostname

        const chain = await new Promise<Array<{ subject: string; issuer: string; valid_from: string; valid_to: string; serial: string }>>((resolve, reject) => {
          const socket = tls.connect(443, hostname, { servername: hostname }, () => {
            const cert = socket.getPeerCertificate(true) as any
            if (!cert || !cert.subject) {
              socket.destroy()
              return reject(new Error('No certificate returned'))
            }

            const certs: Array<{ subject: string; issuer: string; valid_from: string; valid_to: string; serial: string }> = []
            let current = cert
            const seen = new Set<string>()

            while (current && current.subject) {
              const serial = current.serialNumber || ''
              if (seen.has(serial)) break
              seen.add(serial)
              certs.push({
                subject: typeof current.subject === 'object' ? (current.subject.CN || JSON.stringify(current.subject)) : String(current.subject),
                issuer: typeof current.issuer === 'object' ? (current.issuer.CN || JSON.stringify(current.issuer)) : String(current.issuer),
                valid_from: current.valid_from || '',
                valid_to: current.valid_to || '',
                serial,
              })
              if (current.issuerCertificate && current.issuerCertificate !== current && current.issuerCertificate.serialNumber !== serial) {
                current = current.issuerCertificate
              } else {
                break
              }
            }

            socket.destroy()
            resolve(certs)
          })
          socket.setTimeout(10000)
          socket.on('timeout', () => { socket.destroy(); reject(new Error('Connection timeout')) })
          socket.on('error', (err: Error) => { reject(err) })
        })

        const isComplete = chain.length > 0 && chain[chain.length - 1].subject === chain[chain.length - 1].issuer

        return withJson({
          url: normalized,
          domain: hostname,
          chain,
          chain_length: chain.length,
          complete: isComplete,
          score: isComplete ? 100 : 50,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to validate SSL certificate chain'
        return withJson({ error: message }, { status: 502 })
      }
    }

    // --- HTTP Header Fingerprint ---
    if (path === '/api/header-fingerprint') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'header-fingerprint')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const resp = await fetch(normalized, { signal: AbortSignal.timeout(10000), redirect: 'follow' })
        const headerNames: string[] = []
        resp.headers.forEach((_val: string, key: string) => { headerNames.push(key) })
        headerNames.sort()

        const hash = createHash('sha256').update(headerNames.join(',')).digest('hex')

        return withJson({
          url: normalized,
          headers_count: headerNames.length,
          header_names: headerNames,
          fingerprint: 'sha256:' + hash,
          score: 100,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to generate header fingerprint'
        return withJson({ error: message }, { status: 502 })
      }
    }

    // --- Content-Type Sniffer ---
    if (path === '/api/content-type') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'content-type')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const resp = await fetch(normalized, { signal: AbortSignal.timeout(10000), redirect: 'follow' })
        const declaredType = resp.headers.get('content-type') || 'unknown'
        const body = await resp.arrayBuffer()
        const bytes = new Uint8Array(body)
        const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes.slice(0, 2048))

        let detectedType = 'unknown'
        if (bytes.length >= 4 && bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4E && bytes[3] === 0x47) {
          detectedType = 'image/png'
        } else if (bytes.length >= 3 && bytes[0] === 0xFF && bytes[1] === 0xD8 && bytes[2] === 0xFF) {
          detectedType = 'image/jpeg'
        } else if (bytes.length >= 4 && bytes[0] === 0x47 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x38) {
          detectedType = 'image/gif'
        } else if (bytes.length >= 4 && bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46) {
          detectedType = 'application/pdf'
        } else {
          const trimmed = text.trimStart()
          if (trimmed.startsWith('<!DOCTYPE') || trimmed.startsWith('<!doctype') || trimmed.startsWith('<html') || trimmed.startsWith('<HTML')) {
            detectedType = 'text/html'
          } else if (trimmed.startsWith('<?xml') || trimmed.startsWith('<rss') || trimmed.startsWith('<feed')) {
            detectedType = 'application/xml'
          } else {
            try { JSON.parse(trimmed); detectedType = 'application/json' } catch { detectedType = 'text/plain' }
          }
        }

        const declaredBase = declaredType.split(';')[0].trim().toLowerCase()
        const detectedBase = detectedType.toLowerCase()
        const match = declaredBase === detectedBase || declaredBase.includes(detectedBase) || detectedBase.includes(declaredBase)
        const xContentTypeOptions = resp.headers.get('x-content-type-options') || null

        let score = 100
        if (!match) score -= 40
        if (!xContentTypeOptions) score -= 10

        return withJson({
          url: normalized,
          declared_type: declaredType,
          detected_type: detectedType,
          match,
          x_content_type_options: xContentTypeOptions,
          score: Math.max(0, score),
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to analyze content type'
        return withJson({ error: message }, { status: 502 })
      }
    }

    // --- Cookie Security Audit ---
    if (path === '/api/cookie-security') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'cookie-security')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const resp = await fetch(normalized, { signal: AbortSignal.timeout(10000), redirect: 'follow' })
        const setCookieHeaders = resp.headers.getSetCookie ? resp.headers.getSetCookie() : []

        const cookies: Array<{name: string; value_preview: string; secure: boolean; httpOnly: boolean; sameSite: string | null; path: string | null; domain: string | null; expires: string | null; max_age: number | null; score: number}> = []

        for (const raw of setCookieHeaders) {
          const parts = raw.split(';').map((s: string) => s.trim())
          const [nameVal, ...attrs] = parts
          const eqIdx = nameVal.indexOf('=')
          const name = eqIdx > -1 ? nameVal.slice(0, eqIdx).trim() : nameVal.trim()
          const value = eqIdx > -1 ? nameVal.slice(eqIdx + 1).trim() : ''

          let secure = false, httpOnly = false, sameSite: string | null = null
          let path: string | null = null, domain: string | null = null
          let expires: string | null = null, maxAge: number | null = null

          for (const attr of attrs) {
            const lower = attr.toLowerCase()
            if (lower === 'secure') { secure = true; continue }
            if (lower === 'httponly') { httpOnly = true; continue }
            if (lower.startsWith('samesite=')) { sameSite = attr.split('=')[1]?.trim() || null; continue }
            if (lower.startsWith('path=')) { path = attr.split('=')[1]?.trim() || null; continue }
            if (lower.startsWith('domain=')) { domain = attr.split('=')[1]?.trim() || null; continue }
            if (lower.startsWith('expires=')) { expires = attr.slice(8).trim(); continue }
            if (lower.startsWith('max-age=')) { maxAge = parseInt(attr.split('=')[1]?.trim() || '0', 10); continue }
          }

          let cookieScore = 100
          const isHttps = normalized.startsWith('https')
          if (isHttps && !secure) cookieScore -= 25
          if (!httpOnly) cookieScore -= 25
          if (!sameSite) cookieScore -= 20

          cookies.push({ name, value_preview: value.slice(0, 8) + (value.length > 8 ? '...' : ''), secure, httpOnly, sameSite, path, domain, expires, max_age: maxAge, score: Math.max(0, cookieScore) })
        }

        const avgScore = cookies.length > 0 ? Math.round(cookies.reduce((s, c) => s + c.score, 0) / cookies.length) : 100

        return withJson({
          url: normalized,
          cookies,
          total: cookies.length,
          score: avgScore,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to audit cookies'
        return withJson({ error: message }, { status: 502 })
      }
    }

    // --- DNS CAA Record Checker ---
    if (path === '/api/dns-caa') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'dns-caa')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const domain = new URL(normalized).hostname

        const dohUrl = 'https://cloudflare-dns.com/dns-query?name=' + encodeURIComponent(domain) + '&type=CAA'
        const dohResp = await fetch(dohUrl, {
          headers: { Accept: 'application/dns-json' },
          signal: AbortSignal.timeout(10000),
        })
        const dohData = await dohResp.json() as { Answer?: Array<{ type: number; data: string }> }

        const caaRecords: Array<{ flags: number; tag: string; value: string }> = []
        if (dohData.Answer) {
          for (const ans of dohData.Answer) {
            if (ans.type === 257) {
              const parts = ans.data.match(/^(\d+)\s+(\w+)\s+"?(.+?)"?$/)
              if (parts) {
                caaRecords.push({ flags: parseInt(parts[1], 10), tag: parts[2], value: parts[3] })
              }
            }
          }
        }

        const hasCaa = caaRecords.length > 0
        const score = hasCaa ? 100 : 50

        return withJson({
          url: normalized,
          domain,
          caa_records: caaRecords,
          has_caa: hasCaa,
          score,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to check DNS CAA records'
        return withJson({ error: message }, { status: 502 })
      }
    }

    // --- SRI Scanner ---
    if (path === '/api/sri-scan') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'sri-scan')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const resp = await fetch(normalized, {
          signal: AbortSignal.timeout(10000),
          headers: { 'User-Agent': 'Pulse-Bot/1.0' },
          redirect: 'follow',
        })
        const html = await resp.text()

        const resources: Array<{ tag: string; src: string; has_integrity: boolean; integrity_value: string | null }> = []

        // Match <script src="..."> tags
        const scriptRegex = /<script\s[^>]*src\s*=\s*["']([^"']+)["'][^>]*>/gi
        let match: RegExpExecArray | null
        while ((match = scriptRegex.exec(html)) !== null) {
          const fullTag = match[0]
          const src = match[1]
          const integrityMatch = fullTag.match(/integrity\s*=\s*["']([^"']+)["']/i)
          resources.push({
            tag: 'script',
            src,
            has_integrity: !!integrityMatch,
            integrity_value: integrityMatch ? integrityMatch[1] : null,
          })
        }

        // Match <link rel="stylesheet" href="..."> tags
        const linkRegex = /<link\s[^>]*rel\s*=\s*["']stylesheet["'][^>]*>/gi
        while ((match = linkRegex.exec(html)) !== null) {
          const fullTag = match[0]
          const hrefMatch = fullTag.match(/href\s*=\s*["']([^"']+)["']/i)
          if (!hrefMatch) continue
          const src = hrefMatch[1]
          const integrityMatch = fullTag.match(/integrity\s*=\s*["']([^"']+)["']/i)
          resources.push({
            tag: 'link',
            src,
            has_integrity: !!integrityMatch,
            integrity_value: integrityMatch ? integrityMatch[1] : null,
          })
        }

        const total = resources.length
        const protectedCount = resources.filter(r => r.has_integrity).length
        const unprotected = total - protectedCount
        const score = total === 0 ? 100 : Math.round((protectedCount / total) * 100)

        return withJson({
          url: normalized,
          resources,
          total,
          protected: protectedCount,
          unprotected,
          score,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to scan for SRI'
        return withJson({ error: message }, { status: 502 })
      }
    }

    // --- HSTS Deep Analysis ---
    if (path === '/api/hsts-analysis') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'hsts-analysis')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const resp = await fetch(normalized, {
          signal: AbortSignal.timeout(10000),
          headers: { 'User-Agent': 'Pulse-Bot/1.0' },
          redirect: 'follow',
        })

        const hstsHeader = resp.headers.get('strict-transport-security')
        if (!hstsHeader) {
          return withJson({
            url: normalized,
            has_hsts: false,
            max_age: null,
            include_subdomains: false,
            preload: false,
            max_age_days: null,
            meets_minimum: false,
            score: 0,
          })
        }

        const maxAgeMatch = hstsHeader.match(/max-age\s*=\s*(\d+)/i)
        const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0
        const includeSubdomains = /includeSubDomains/i.test(hstsHeader)
        const preload = /preload/i.test(hstsHeader)
        const maxAgeDays = Math.round(maxAge / 86400)
        const meetsMinimum = maxAge >= 31536000

        let score = 0
        if (maxAge > 0) score += 25
        if (meetsMinimum) score += 25
        if (includeSubdomains) score += 25
        if (preload) score += 25

        return withJson({
          url: normalized,
          has_hsts: true,
          max_age: maxAge,
          include_subdomains: includeSubdomains,
          preload,
          max_age_days: maxAgeDays,
          meets_minimum: meetsMinimum,
          score,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to analyze HSTS'
        return withJson({ error: message }, { status: 502 })
      }
    }

    // --- Certificate Transparency Log Checker ---
    if (path === '/api/ct-logs') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'ct-logs')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const domain = new URL(normalized).hostname

        const crtUrl = 'https://crt.sh/?q=' + encodeURIComponent(domain) + '&output=json&exclude=expired'
        const crtResp = await fetch(crtUrl, {
          signal: AbortSignal.timeout(15000),
        })
        const crtData = await crtResp.json() as Array<{ issuer_name: string; not_before: string; not_after: string; serial_number: string; name_value: string }>

        const certificates = crtData.slice(0, 50).map(c => ({
          issuer_name: c.issuer_name || '',
          not_before: c.not_before || '',
          not_after: c.not_after || '',
          serial_number: c.serial_number || '',
        }))

        return withJson({
          url: normalized,
          domain,
          certificates,
          total: crtData.length,
          score: crtData.length > 0 ? 100 : 0,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to query CT logs'
        return withJson({ error: message }, { status: 502 })
      }
    }

    // --- HTTP/3 Alt-Svc Detector ---
    if (path === '/api/http3') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'http3')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const resp = await fetch(normalized, {
          method: 'HEAD',
          redirect: 'follow',
          signal: AbortSignal.timeout(10000),
        })

        const altSvc = resp.headers.get('alt-svc') || ''
        const protocols: string[] = []
        if (altSvc) {
          const matches = altSvc.matchAll(/\b(h3(?:-\d+)?)\b/g)
          for (const m of matches) {
            if (!protocols.includes(m[1])) protocols.push(m[1])
          }
        }

        const hasHttp3 = protocols.length > 0

        return withJson({
          url: normalized,
          has_http3: hasHttp3,
          alt_svc: altSvc || null,
          protocols,
          score: hasHttp3 ? 100 : 0,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to detect HTTP/3'
        return withJson({ error: message }, { status: 502 })
      }
    }

    // --- DNS DMARC Record Analyzer ---
    if (path === '/api/dns-dmarc') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'dns-dmarc')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const domain = new URL(normalized).hostname

        const dohUrl = 'https://cloudflare-dns.com/dns-query?name=' + encodeURIComponent('_dmarc.' + domain) + '&type=TXT'
        const dohResp = await fetch(dohUrl, {
          headers: { Accept: 'application/dns-json' },
          signal: AbortSignal.timeout(10000),
        })
        const dohData = await dohResp.json() as { Answer?: Array<{ type: number; data: string }> }

        let record = ''
        if (dohData.Answer) {
          for (const ans of dohData.Answer) {
            if (ans.type === 16) {
              const txt = ans.data.replace(/^"|"$/g, '')
              if (txt.startsWith('v=DMARC1')) {
                record = txt
                break
              }
            }
          }
        }

        const hasDmarc = record.length > 0
        const tags: Record<string, string> = {}
        if (hasDmarc) {
          const parts = record.split(';')
          for (const part of parts) {
            const trimmed = part.trim()
            const eqIdx = trimmed.indexOf('=')
            if (eqIdx > 0) {
              const key = trimmed.slice(0, eqIdx).trim()
              const value = trimmed.slice(eqIdx + 1).trim()
              tags[key] = value
            }
          }
        }

        const policy = tags['p'] || null

        return withJson({
          url: normalized,
          domain,
          has_dmarc: hasDmarc,
          record: record || null,
          policy,
          tags,
          score: hasDmarc ? 100 : 0,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to check DMARC records'
        return withJson({ error: message }, { status: 502 })
      }
    }

    // --- DNS MX Record Checker ---
    if (path === '/api/dns-mx') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'dns-mx')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const domain = new URL(normalized).hostname

        const dohUrl = 'https://cloudflare-dns.com/dns-query?name=' + encodeURIComponent(domain) + '&type=MX'
        const dohResp = await fetch(dohUrl, {
          headers: { Accept: 'application/dns-json' },
          signal: AbortSignal.timeout(10000),
        })
        const dohData = await dohResp.json() as { Answer?: Array<{ type: number; data: string }> }

        const mxRecords: Array<{ priority: number; exchange: string }> = []
        if (dohData.Answer) {
          for (const ans of dohData.Answer) {
            if (ans.type === 15) {
              const parts = ans.data.match(/^(\d+)\s+(.+)$/)
              if (parts) {
                mxRecords.push({
                  priority: parseInt(parts[1], 10),
                  exchange: parts[2].replace(/\.$/, ''),
                })
              }
            }
          }
        }

        mxRecords.sort((a, b) => a.priority - b.priority)

        const hasMx = mxRecords.length > 0
        const score = hasMx ? 100 : 0

        return withJson({
          url: normalized,
          domain,
          mx_records: mxRecords,
          has_mx: hasMx,
          total: mxRecords.length,
          score,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to check DNS MX records'
        return withJson({ error: message }, { status: 502 })
      }
    }

    // --- DNS SPF Record Analyzer ---
    if (path === '/api/dns-spf') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'dns-spf')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const domain = new URL(normalized).hostname

        const dohUrl = 'https://cloudflare-dns.com/dns-query?name=' + encodeURIComponent(domain) + '&type=TXT'
        const dohResp = await fetch(dohUrl, {
          headers: { Accept: 'application/dns-json' },
          signal: AbortSignal.timeout(10000),
        })
        const dohData = await dohResp.json() as { Answer?: Array<{ type: number; data: string }> }

        let record = ''
        if (dohData.Answer) {
          for (const ans of dohData.Answer) {
            if (ans.type === 16) {
              const txt = ans.data.replace(/^"|"$/g, '').replace(/"\s*"/g, '')
              if (txt.startsWith('v=spf1')) {
                record = txt
                break
              }
            }
          }
        }

        const hasSpf = record.length > 0
        const mechanisms: Array<{ type: string; value: string }> = []
        let allPolicy: string | null = null

        if (hasSpf) {
          const parts = record.split(/\s+/)
          for (const part of parts) {
            if (part === 'v=spf1') continue
            const match = part.match(/^([+\-~?]?)(.+)$/)
            if (!match) continue
            const qualifier = match[1] || '+'
            const mechanism = match[2]

            if (mechanism.startsWith('include:')) {
              mechanisms.push({ type: 'include', value: mechanism.slice(8) })
            } else if (mechanism.startsWith('a:') || mechanism === 'a') {
              mechanisms.push({ type: 'a', value: mechanism === 'a' ? domain : mechanism.slice(2) })
            } else if (mechanism.startsWith('mx:') || mechanism === 'mx') {
              mechanisms.push({ type: 'mx', value: mechanism === 'mx' ? domain : mechanism.slice(3) })
            } else if (mechanism.startsWith('ip4:')) {
              mechanisms.push({ type: 'ip4', value: mechanism.slice(4) })
            } else if (mechanism.startsWith('ip6:')) {
              mechanisms.push({ type: 'ip6', value: mechanism.slice(4) })
            } else if (mechanism.startsWith('redirect=')) {
              mechanisms.push({ type: 'redirect', value: mechanism.slice(9) })
            } else if (mechanism.startsWith('exists:')) {
              mechanisms.push({ type: 'exists', value: mechanism.slice(7) })
            } else if (mechanism === 'ptr' || mechanism.startsWith('ptr:')) {
              mechanisms.push({ type: 'ptr', value: mechanism === 'ptr' ? domain : mechanism.slice(4) })
            } else if (mechanism === 'all') {
              allPolicy = qualifier + 'all'
            }
          }
        }

        return withJson({
          url: normalized,
          domain,
          has_spf: hasSpf,
          record: record || null,
          mechanisms,
          all_policy: allPolicy,
          score: hasSpf ? 100 : 0,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to check SPF records'
        return withJson({ error: message }, { status: 502 })
      }
    }

    // --- DNS NS Record Checker ---
    if (path === '/api/dns-ns') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'dns-ns')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const domain = new URL(normalized).hostname

        const dohUrl = 'https://cloudflare-dns.com/dns-query?name=' + encodeURIComponent(domain) + '&type=NS'
        const dohResp = await fetch(dohUrl, {
          headers: { Accept: 'application/dns-json' },
          signal: AbortSignal.timeout(10000),
        })
        const dohData = await dohResp.json() as { Answer?: Array<{ type: number; data: string }> }

        const nameservers: string[] = []
        if (dohData.Answer) {
          for (const ans of dohData.Answer) {
            if (ans.type === 2) {
              nameservers.push(ans.data.replace(/\.$/, ''))
            }
          }
        }

        nameservers.sort()

        return withJson({
          url: normalized,
          domain,
          nameservers,
          has_ns: nameservers.length > 0,
          total: nameservers.length,
          score: nameservers.length > 0 ? 100 : 0,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to check DNS NS records'
        return withJson({ error: message }, { status: 502 })
      }
    }

    // --- DNS AAAA Record Checker ---
    if (path === '/api/dns-aaaa') {
      if (request.method !== 'GET') {
        return withJson({ error: 'Method Not Allowed' }, { status: 405 })
      }

      const target = url.searchParams.get('url')
      if (!target) {
        return withJson({ error: 'url parameter required' }, { status: 400 })
      }

      const apiKey = request.headers.get('X-API-Key')?.trim() || null
      const clientIp = getClientIp(request)
      const rl = getEndpointRateLimit(clientIp, apiKey, 'dns-aaaa')
      if (!rl.allowed) {
        return withJson({ error: 'Rate limit exceeded', limit: rl.limit, resetAt: rl.resetAt }, { status: 429 })
      }

      try {
        const normalized = normalizeUrl(target)
        const domain = new URL(normalized).hostname

        const dohUrl = 'https://cloudflare-dns.com/dns-query?name=' + encodeURIComponent(domain) + '&type=AAAA'
        const dohResp = await fetch(dohUrl, {
          headers: { Accept: 'application/dns-json' },
          signal: AbortSignal.timeout(10000),
        })
        const dohData = await dohResp.json() as { Answer?: Array<{ type: number; data: string }> }

        const aaaaRecords: string[] = []
        if (dohData.Answer) {
          for (const ans of dohData.Answer) {
            if (ans.type === 28) {
              aaaaRecords.push(ans.data)
            }
          }
        }

        return withJson({
          url: normalized,
          domain,
          aaaa_records: aaaaRecords,
          has_ipv6: aaaaRecords.length > 0,
          total: aaaaRecords.length,
          score: aaaaRecords.length > 0 ? 100 : 0,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to check DNS AAAA records'
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
