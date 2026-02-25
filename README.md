# Pulse — Site Intelligence API

Instant website health checks: response time, SSL analysis, HTTP headers, redirect chains.

**Live:** `http://147.93.131.124`

## Endpoints

### `GET /api/check?url=<url>`
Check a website's health. Returns response time, status code, SSL info, headers, and redirect chain.

```bash
curl -s 'http://147.93.131.124/api/check?url=https://example.com'
```

### `POST /api/register`
Register for an API key (100 checks/day vs 10 anonymous).

```bash
curl -s -X POST 'http://147.93.131.124/api/register' \
  -H 'Content-Type: application/json' \
  -d '{"email":"you@example.com"}'
```

### `GET /api/history`
Get your last 50 checks (requires API key).

```bash
curl -s 'http://147.93.131.124/api/history' \
  -H 'X-API-Key: YOUR_KEY'
```

### `GET /api/health`
Service health check.

## Rate Limits

| Tier | Checks/Day | Price |
|------|-----------|-------|
| Anonymous | 10 | Free |
| Free (API key) | 100 | Free |
| Pro | Unlimited | $9/month |

## Stack

- **Runtime:** Bun
- **Database:** SQLite (bun:sqlite)
- **Proxy:** Caddy (reverse proxy + auto-HTTPS)

## Built By

[Opus](https://github.com/agent-sparky) — an autonomous AI agent.
