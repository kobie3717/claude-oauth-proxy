# Claude OAuth Proxy + Anti-Ban Engine

A local proxy that uses your Claude Pro/Max subscription as a standard Anthropic API endpoint, with built-in anti-detection stealth layer.

## Features

### Core Proxy
- **OAuth Authentication** — Uses Claude setup-token for subscription access
- **Full API Compatibility** — Drop-in replacement for Anthropic API
- **Streaming Support** — Full SSE streaming passthrough
- **PM2 Ready** — Production-grade process management

### 🛡️ Anti-Ban Engine
Makes proxy traffic **indistinguishable** from real Claude Code CLI usage:

| Layer | What it does |
|-------|-------------|
| **Human Timing** | Random delays (0.6-3.2s), thinking pauses, coffee breaks, session patterns |
| **Tool Injection** | Injects real Claude Code tool definitions (Bash, Read, Write, Edit, Glob, Grep, etc.) |
| **System Prompt** | Rewrites system prompt to match Claude Code's exact format and structure |
| **Header Fingerprint** | Rotates CLI version, platform strings, includes all telemetry headers |
| **Session Simulation** | Coding bursts (3-10 req) → pause → burst. Sessions with natural breaks |
| **Quiet Hours** | Reduced activity during configurable sleep hours (default: 21:00-04:00 UTC) |
| **Rate Governance** | Per-minute (8), per-hour (100), per-day (600) limits matching human capacity |

## Quick Start

```bash
# 1. Generate a setup token (requires Claude Code CLI)
claude setup-token

# 2. Start the proxy
node proxy.mjs --token sk-ant-oat01-your-token-here

# 3. Use it
curl http://localhost:4321/v1/messages \
  -H "Content-Type: application/json" \
  -H "x-api-key: anything" \
  -H "anthropic-version: 2023-06-01" \
  -d '{
    "model": "claude-sonnet-4-20250514",
    "max_tokens": 256,
    "messages": [{"role": "user", "content": "Hello!"}]
  }'
```

## Production Setup (PM2)

```bash
pm2 start ecosystem.config.js
pm2 save
```

## Endpoints

| Path | Description |
|------|-------------|
| `GET /health` | Proxy status + anti-ban stats |
| `POST /v1/messages` | Chat completions (streaming supported) |
| `POST /v1/messages/count_tokens` | Token counting |

## Configuration

### Token Sources (checked in order)
1. `--token` CLI flag
2. `CLAUDE_CODE_OAUTH_TOKEN` environment variable
3. Saved token in `~/.config/claude-oauth-proxy/token`
4. Interactive prompt

### Environment Variables
| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `4321` | Proxy listen port |
| `HOST` | `127.0.0.1` | Bind address |
| `CLAUDE_CODE_OAUTH_TOKEN` | — | OAuth token |

### Anti-Ban Tuning

Edit the `CONFIG` object in `anti-ban.mjs` to adjust:
- Delay ranges and probabilities
- Rate limits per minute/hour/day
- Session burst size and break duration
- Quiet hours (timezone)
- Claude Code version pool

## How It Works

```
Your App → Proxy (anti-ban gate) → Anthropic API
              ↓
    1. Rate limit check
    2. Session simulation delay
    3. Human thinking delay
    4. Tool definition injection
    5. System prompt rewrite
    6. Header fingerprint rotation
    7. Forward with OAuth Bearer auth
```

Every request that reaches Anthropic looks exactly like a real Claude Code CLI session:
- Correct user-agent and telemetry headers
- Full Claude Code tool definitions attached
- System prompt matches Claude Code's format
- Request timing follows human patterns

## Security

- Binds to `127.0.0.1` only — not accessible from other machines
- Token stored with `0600` permissions
- No data logging — only method, path, status, and model name
- Client API keys are ignored (any value works, it's localhost)

## Disclaimer

This uses the same OAuth client ID and headers as Claude Code. It is **not officially sanctioned** by Anthropic. They could change required headers, rotate client identity, or block this approach at any time.

The setup-token is valid for ~1 year but can be revoked. Always have a regular API key as a fallback.

## License

MIT
