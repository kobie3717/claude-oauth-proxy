#!/usr/bin/env node

/**
 * Claude OAuth Proxy
 * 
 * A local proxy that exposes an Anthropic-compatible /v1/messages endpoint
 * using your Claude Pro/Max subscription via OAuth setup-token.
 * 
 * Usage:
 *   node proxy.mjs                              Start the proxy
 *   node proxy.mjs --token sk-ant-oat01-...     Start with token inline
 *   node proxy.mjs status                       Check if token is configured
 *   node proxy.mjs help                         Show help
 * 
 * Token can be provided via:
 *   1. --token flag
 *   2. CLAUDE_CODE_OAUTH_TOKEN env var
 *   3. Prompted on first run (saved to config)
 * 
 * Then point any Anthropic-compatible app at http://localhost:4321
 */

import { createServer } from "node:http";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { antiBanGate, getStats, transformRequest, recordError, recordSuccess, analyzeResponse, finishSlot } from "./anti-ban.mjs";

// --- Load .env file ---

const __dirname = dirname(fileURLToPath(import.meta.url));
const envPath = join(__dirname, ".env");
if (existsSync(envPath)) {
  const envContent = await readFile(envPath, "utf-8");
  for (const line of envContent.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eq = trimmed.indexOf("=");
    if (eq === -1) continue;
    const key = trimmed.slice(0, eq).trim();
    const value = trimmed.slice(eq + 1).trim();
    if (!process.env[key]) process.env[key] = value;
  }
}

// --- Constants ---

const ANTHROPIC_API = "https://api.anthropic.com";
const CONFIG_DIR = join(homedir(), ".config", "claude-oauth-proxy");
const TOKEN_FILE = join(CONFIG_DIR, "token");
const DEFAULT_PORT = 4321;
const DEFAULT_HOST = "127.0.0.1";

// Mimic Claude Code's identity exactly
const CLAUDE_CODE_VERSION = "2.1.2";

// Required system prompt prefix for OAuth tokens
const CLAUDE_CODE_SYSTEM_PREFIX = "You are Claude Code, Anthropic's official CLI for Claude.";

// Beta features that Claude Code sends
const BETA_FEATURES = [
  "claude-code-20250219",
  "oauth-2025-04-20",
  "fine-grained-tool-streaming-2025-05-14",
  "interleaved-thinking-2025-05-14",
];

// Headers that make the request look like Claude Code
const CLAUDE_CODE_HEADERS = {
  "accept": "application/json",
  "anthropic-dangerous-direct-browser-access": "true",
  "anthropic-beta": BETA_FEATURES.join(","),
  "user-agent": `claude-cli/${CLAUDE_CODE_VERSION} (external, cli)`,
  "x-app": "cli",
};

// --- Token Management ---

async function ensureConfigDir() {
  if (!existsSync(CONFIG_DIR)) {
    await mkdir(CONFIG_DIR, { recursive: true, mode: 0o700 });
  }
}

async function loadToken() {
  try {
    const token = (await readFile(TOKEN_FILE, "utf-8")).trim();
    if (token) return token;
  } catch {}
  return null;
}

async function saveToken(token) {
  await ensureConfigDir();
  await writeFile(TOKEN_FILE, token.trim(), { mode: 0o600 });
}

async function resolveToken(cliToken) {
  // 1. CLI flag
  if (cliToken) {
    await saveToken(cliToken);
    return cliToken;
  }

  // 2. Environment variable
  const envToken = process.env.CLAUDE_CODE_OAUTH_TOKEN;
  if (envToken) return envToken;

  // 3. Saved token file
  const savedToken = await loadToken();
  if (savedToken) return savedToken;

  // 4. Prompt
  console.log("\n🔐 No OAuth token found.\n");
  console.log("Run `claude setup-token` to generate one, then paste it here:\n");
  const token = await readLine("> ");
  if (!token.trim()) {
    console.error("❌ No token provided.");
    process.exit(1);
  }
  await saveToken(token.trim());
  console.log(`✅ Token saved to ${TOKEN_FILE}\n`);
  return token.trim();
}

// --- Request Transformation ---

/**
 * Ensure the system prompt starts with Claude Code's identity prefix.
 * This is required for OAuth token requests to be accepted.
 */
function ensureClaudeCodeSystemPrompt(body) {
  if (!body) return body;

  let parsed;
  try {
    parsed = typeof body === "string" ? JSON.parse(body) : body;
  } catch {
    return body;
  }

  // Handle system as string
  if (typeof parsed.system === "string") {
    if (!parsed.system.startsWith(CLAUDE_CODE_SYSTEM_PREFIX)) {
      parsed.system = [
        {
          type: "text",
          text: CLAUDE_CODE_SYSTEM_PREFIX,
          cache_control: { type: "ephemeral" },
        },
        {
          type: "text",
          text: parsed.system,
          cache_control: { type: "ephemeral" },
        },
      ];
    }
  }
  // Handle system as array of content blocks
  else if (Array.isArray(parsed.system)) {
    const firstText = parsed.system.find(b => b.type === "text");
    if (!firstText || !firstText.text.startsWith(CLAUDE_CODE_SYSTEM_PREFIX)) {
      parsed.system.unshift({
        type: "text",
        text: CLAUDE_CODE_SYSTEM_PREFIX,
        cache_control: { type: "ephemeral" },
      });
    }
  }
  // No system prompt at all — add one
  else if (parsed.system === undefined || parsed.system === null) {
    parsed.system = [
      {
        type: "text",
        text: CLAUDE_CODE_SYSTEM_PREFIX,
        cache_control: { type: "ephemeral" },
      },
    ];
  }

  return JSON.stringify(parsed);
}

// --- Proxy Server ---

function startProxy(port, token) {
  let requestCount = 0;

  const server = createServer(async (req, res) => {
    // CORS preflight
    if (req.method === "OPTIONS") {
      res.writeHead(204, {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "*",
      });
      res.end();
      return;
    }

    // Health check
    if (req.url === "/health" && req.method === "GET") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({
        status: "ok",
        requests_served: requestCount,
        token_prefix: token.slice(0, 15) + "...",
        antiBan: getStats(),
      }));
      return;
    }

    // Only proxy /v1/* paths
    if (!req.url.startsWith("/v1/")) {
      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({
        error: "Not found",
        hint: "Use /v1/messages or other Anthropic API paths",
      }));
      return;
    }

    // Collect request body
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const rawBody = Buffer.concat(chunks);

    try {
      // --- Anti-Ban Gate ---
      const gate = await antiBanGate();
      if (!gate.proceed) {
        console.log(`⏸  Anti-ban: ${gate.reason}`);
        res.writeHead(429, { 
          "Content-Type": "application/json",
          "Retry-After": Math.ceil(gate.waitMs / 1000).toString(),
        });
        res.end(JSON.stringify({
          type: "error",
          error: {
            type: "rate_limit_error",
            message: gate.reason,
            retry_after_ms: gate.waitMs,
          },
        }));
        return;
      }

      // Transform the body: system prompt + tool injection + Claude Code fingerprint
      const transformedBody = req.method === "POST"
        ? transformRequest(rawBody.toString())
        : undefined;

      // Build upstream headers — Claude Code style, with anti-ban variation
      const upstreamHeaders = {
        ...CLAUDE_CODE_HEADERS,
        ...gate.headers, // Anti-ban varied headers (user-agent rotation etc)
        "content-type": req.headers["content-type"] || "application/json",
        "authorization": `Bearer ${token}`,
      };

      // Forward anthropic-version if client sends it, otherwise use a sensible default
      upstreamHeaders["anthropic-version"] = req.headers["anthropic-version"] || "2023-06-01";

      // If client sends anthropic-beta, merge with ours (ours take priority for required ones)
      if (req.headers["anthropic-beta"]) {
        const clientBetas = req.headers["anthropic-beta"].split(",").map(s => s.trim());
        const ourBetas = new Set(BETA_FEATURES);
        const merged = [...BETA_FEATURES];
        for (const beta of clientBetas) {
          if (!ourBetas.has(beta)) merged.push(beta);
        }
        upstreamHeaders["anthropic-beta"] = merged.join(",");
      }

      // Proxy the request
      const upstreamUrl = `${ANTHROPIC_API}${req.url}`;
      const upstreamRes = await fetch(upstreamUrl, {
        method: req.method,
        headers: upstreamHeaders,
        body: req.method !== "GET" && req.method !== "HEAD" ? transformedBody || rawBody : undefined,
      });

      // Forward response headers
      const responseHeaders = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Expose-Headers": "*",
      };
      for (const [key, value] of upstreamRes.headers) {
        if (["transfer-encoding", "connection", "keep-alive", "content-encoding"].includes(key.toLowerCase())) continue;
        responseHeaders[key] = value;
      }

      res.writeHead(upstreamRes.status, responseHeaders);

      // Stream the response + capture first chunk for ban detection
      let firstChunk = "";
      let capturedBytes = 0;
      const CAPTURE_LIMIT = 512;

      if (upstreamRes.body) {
        const reader = upstreamRes.body.getReader();
        try {
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            res.write(value);
            // Capture beginning of response for ban signal analysis
            if (capturedBytes < CAPTURE_LIMIT) {
              firstChunk += new TextDecoder().decode(value).slice(0, CAPTURE_LIMIT - capturedBytes);
              capturedBytes += value.length;
            }
          }
        } catch (err) {
          if (!res.destroyed) {
            console.error(`  ↳ Stream error: ${err.message}`);
          }
        }
      }

      res.end();
      requestCount++;

      // Release concurrency slot
      if (gate._releaseSlot) gate._releaseSlot();

      // Analyze response for ban signals
      const status = upstreamRes.status;
      const signals = analyzeResponse(status, upstreamRes.headers, firstChunk);

      if (signals.isBan) {
        recordError(status);
        console.error(`🚨 BAN SIGNAL: ${signals.signal} (status ${status})`);
      } else if (signals.isThrottle) {
        recordError(status);
        console.warn(`⚠️  THROTTLE: ${signals.signal} (status ${status})`);
      } else if (status >= 200 && status < 300) {
        recordSuccess();
      } else if (status >= 400) {
        recordError(status);
      }

      // Log
      const model = (() => {
        try { return JSON.parse(rawBody.toString()).model || "?"; } catch { return "?"; }
      })();
      const statusIcon = status >= 200 && status < 300 ? "✓" : "✗";
      const stats = getStats();
      console.log(`${statusIcon} ${req.method} ${req.url} → ${status} (${model}) [${stats.requestsThisHour}/hr, burst ${stats.burstProgress}]`);

    } catch (err) {
      // Release slot on error
      if (typeof finishSlot === 'function') finishSlot();
      console.error(`✗ Proxy error: ${err.message}`);
      if (!res.headersSent) {
        res.writeHead(502, { "Content-Type": "application/json" });
        res.end(JSON.stringify({
          type: "error",
          error: {
            type: "proxy_error",
            message: `Failed to reach Anthropic API: ${err.message}`,
          },
        }));
      }
    }
  });

  const host = process.env.HOST || DEFAULT_HOST;
  server.listen(port, host, () => {
    console.log(`\n🚀 Claude OAuth Proxy running at http://${host}:${port}`);
    console.log(`   Proxying to ${ANTHROPIC_API}`);
    console.log(`   Mimicking Claude Code v${CLAUDE_CODE_VERSION}`);
    console.log(`   Token: ${token.slice(0, 15)}...`);
    console.log(`\n📋 Configure your app:`);
    console.log(`   Base URL:  http://${host}:${port}`);
    console.log(`   API Key:   anything (ignored by proxy)\n`);
  });

  // Graceful shutdown
  const shutdown = () => {
    console.log(`\n👋 Shutting down. Served ${requestCount} requests.`);
    server.close(() => process.exit(0));
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

// --- Status Command ---

async function status() {
  const token = await loadToken();
  const envToken = process.env.CLAUDE_CODE_OAUTH_TOKEN;

  console.log("\n🔑 Claude OAuth Proxy — Status\n");

  if (envToken) {
    console.log(`   Environment: CLAUDE_CODE_OAUTH_TOKEN = ${envToken.slice(0, 15)}...`);
  } else {
    console.log(`   Environment: CLAUDE_CODE_OAUTH_TOKEN not set`);
  }

  if (token) {
    console.log(`   Saved token: ${TOKEN_FILE}`);
    console.log(`   Token:       ${token.slice(0, 15)}...`);
  } else {
    console.log(`   Saved token: none`);
  }

  const active = envToken || token;
  console.log(`\n   Status: ${active ? "✅ Ready" : "❌ No token — run `node proxy.mjs --token <token>`"}\n`);
}

// --- Readline Helper ---

function readLine(prompt) {
  return new Promise((resolve) => {
    process.stdout.write(prompt);
    let data = "";
    process.stdin.setEncoding("utf-8");
    process.stdin.resume();
    process.stdin.on("data", (chunk) => {
      data += chunk;
      if (data.includes("\n")) {
        process.stdin.pause();
        resolve(data.trim());
      }
    });
  });
}

// --- CLI ---

const args = process.argv.slice(2);
const command = args.find(a => !a.startsWith("--"));
const tokenFlag = args.includes("--token") ? args[args.indexOf("--token") + 1] : null;
const port = parseInt(process.env.PORT || DEFAULT_PORT);

switch (command) {
  case "status":
    await status();
    break;
  case "help":
  case "--help":
  case "-h":
    console.log(`
Claude OAuth Proxy — Use your Claude Pro/Max subscription as a local API

Usage:
  node proxy.mjs                              Start the proxy
  node proxy.mjs --token sk-ant-oat01-...     Start with token (saves it)
  node proxy.mjs status                       Check token status
  node proxy.mjs help                         Show this help

Token sources (checked in order):
  1. --token flag
  2. CLAUDE_CODE_OAUTH_TOKEN environment variable
  3. Saved token in ${TOKEN_FILE}
  4. Interactive prompt (saved for next time)

Generate a token:
  claude setup-token

Environment:
  PORT                        Proxy port (default: ${DEFAULT_PORT})
  CLAUDE_CODE_OAUTH_TOKEN     OAuth token (alternative to --token)

Once running, point any Anthropic-compatible app at:
  http://127.0.0.1:${DEFAULT_PORT}

Use any value for the API key — the proxy handles auth.
`);
    break;
  default: {
    const token = await resolveToken(tokenFlag);
    if (!token.includes("sk-ant-oat")) {
      console.warn("⚠️  Token doesn't look like an OAuth token (expected sk-ant-oat prefix).");
      console.warn("   This proxy is designed for OAuth setup-tokens, not API keys.");
      console.warn("   Continuing anyway...\n");
    }
    startProxy(port, token);
    break;
  }
}
