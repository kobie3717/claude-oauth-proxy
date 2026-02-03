# Claude OAuth Proxy

A zero-dependency Node.js proxy that lets you use your **Claude Pro/Max subscription** as a standard Anthropic API endpoint. Any app that speaks the Anthropic API can use it — just point it at `http://localhost:4321`.

## How It Works

1. Generate a long-lived OAuth token with `claude setup-token` (Claude Code CLI)
2. Start the proxy — it handles all the Claude Code impersonation headers
3. Any request to `localhost:4321/v1/messages` gets forwarded to `api.anthropic.com` with proper OAuth authentication
4. Your app doesn't need to know about OAuth — it works like a normal API key

### What the proxy does behind the scenes

- Sets the `Authorization: Bearer <token>` header (OAuth uses Bearer, not x-api-key)
- Adds Claude Code identity headers (`user-agent`, `x-app`, `anthropic-beta` flags)
- Injects the required system prompt prefix (`"You are Claude Code..."`) if missing
- Passes everything else through transparently, including streaming

## Requirements

- Node.js 20+ (uses Web Crypto API and native fetch)
- A Claude Pro or Max subscription
- A setup-token from `claude setup-token`

## Quick Start

```bash
# 1. Generate a token (in Claude Code)
claude setup-token

# 2. Start the proxy
node proxy.mjs --token sk-ant-oat01-your-token-here

# 3. Use it (in another terminal)
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

## Commands

| Command | Description |
|---|---|
| `node proxy.mjs` | Start the proxy |
| `node proxy.mjs --token <token>` | Start with token (saves for next time) |
| `node proxy.mjs status` | Check token configuration |
| `node proxy.mjs help` | Show help |

## Token Sources

The proxy checks for a token in this order:

1. `--token` CLI flag
2. `CLAUDE_CODE_OAUTH_TOKEN` environment variable
3. Saved token in `~/.config/claude-oauth-proxy/token`
4. Interactive prompt (saved for next time)

## Configuration

| Env Var | Default | Description |
|---|---|---|
| `PORT` | `4321` | Proxy listen port |
| `CLAUDE_CODE_OAUTH_TOKEN` | — | OAuth token (alternative to --token) |

## Endpoints

All `/v1/*` paths are proxied to Anthropic, including:

| Path | Description |
|---|---|
| `/v1/messages` | Chat completions (streaming supported) |
| `/v1/messages/count_tokens` | Token counting |
| `/health` | Proxy status |

## Technical Details

### Claude Code Impersonation

For OAuth tokens to work, the request must look like it's coming from Claude Code. The proxy handles this by:

1. **Headers**: Sets `user-agent: claude-cli/2.1.2 (external, cli)`, `x-app: cli`, and required `anthropic-beta` flags
2. **Auth**: Uses `Authorization: Bearer <token>` instead of `x-api-key` header
3. **System prompt**: Prepends `"You are Claude Code, Anthropic's official CLI for Claude."` to the system prompt if not already present
4. **Beta features**: Includes `claude-code-20250219`, `oauth-2025-04-20`, `fine-grained-tool-streaming-2025-05-14`, `interleaved-thinking-2025-05-14`

### Security

- **Binds to 127.0.0.1 only** — not accessible from other machines
- Client API keys are ignored (any value works, it's localhost)
- Token file created with 0600 permissions
- No data logging — only method, path, status code, and model name

## ⚠️ Disclaimer

This uses the same OAuth client ID and headers as Claude Code. It is **not officially sanctioned** by Anthropic for third-party use. Anthropic could change the required headers, rotate the client identity, or block this approach at any time.

The setup-token is valid for ~1 year but can be revoked. Always have a regular API key as a fallback plan.
