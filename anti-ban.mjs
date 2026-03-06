/**
 * Anti-Ban Engine for Claude OAuth Proxy
 * 
 * Makes proxy traffic indistinguishable from real Claude Code CLI usage.
 * 
 * Layers:
 * 1. Human timing simulation (delays, bursts, sessions, quiet hours)
 * 2. Claude Code tool definition injection (bash, file edit, etc.)
 * 3. System prompt rewriting (full Claude Code prompt structure)
 * 4. Header fingerprint rotation (version, platform, telemetry)
 * 5. Request shape normalization (conversation patterns)
 * 6. Rate governance (per-minute/hour/day with human distribution)
 * 
 * @license MIT
 */

// ═══════════════════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════════════════

const CONFIG = {
  // --- Timing ---
  delays: {
    min: 600,           // Minimum delay (ms) - fast typer
    max: 3200,          // Maximum delay (ms) - normal thinking
    thinkingChance: 0.2,     // 20% chance of longer thinking pause
    thinkingExtra: [2000, 8000],
    coffeeChance: 0.04,      // 4% chance of a long pause (coffee/distraction)
    coffeeExtra: [12000, 45000],
    firstRequestDelay: [800, 4000], // Delay on first request of session (opening terminal)
  },

  // --- Rate Limits (mimic human capacity) ---
  rates: {
    perMinute: 8,
    perHour: 100,
    perDay: 600,
  },

  // --- Session Simulation ---
  sessions: {
    burstSize: [3, 10],              // Requests per "coding burst"
    burstPause: [8000, 60000],       // Pause between bursts (reading output)
    duration: [600000, 10800000],    // 10min-3hr sessions
    breakTime: [300000, 2400000],    // 5-40min breaks between sessions
  },

  // --- Quiet Hours (UTC) - SA timezone: 23:00-06:00 SAST = 21:00-04:00 UTC ---
  quietHours: {
    startUTC: 21,
    endUTC: 4,
    maxPerHour: 4,   // Occasional late-night coding is normal
  },

  // --- Claude Code Identity ---
  identity: {
    // Version pool — weighted toward recent versions
    versions: [
      { v: "2.1.70", weight: 40 },
      { v: "2.1.69", weight: 25 },
      { v: "2.1.68", weight: 15 },
      { v: "2.1.67", weight: 10 },
      { v: "2.1.66", weight: 5 },
      { v: "2.1.65", weight: 5 },
    ],
    platforms: [
      "(external, cli)",
      "(external, cli, linux)",
    ],
    // Telemetry headers Claude Code sends
    telemetryHeaders: {
      "x-app": "cli",
      "anthropic-dangerous-direct-browser-access": "true",
    },
  },

  // --- Beta Features (must match real Claude Code) ---
  betaFeatures: [
    "claude-code-20250219",
    "oauth-2025-04-20",
    "fine-grained-tool-streaming-2025-05-14",
    "interleaved-thinking-2025-05-14",
  ],
};

// ═══════════════════════════════════════════════════════════════════
// CLAUDE CODE TOOL DEFINITIONS (injected into every request)
// ═══════════════════════════════════════════════════════════════════

const CLAUDE_CODE_TOOLS = [
  {
    name: "Bash",
    description: "Executes a bash command in the user's shell. Use for file operations, running scripts, installing packages, etc.",
    input_schema: {
      type: "object",
      properties: {
        command: { type: "string", description: "The bash command to execute" },
        timeout: { type: "number", description: "Optional timeout in seconds" }
      },
      required: ["command"]
    }
  },
  {
    name: "Read",
    description: "Reads the contents of a file at the specified path.",
    input_schema: {
      type: "object",
      properties: {
        file_path: { type: "string", description: "The path of the file to read" },
        offset: { type: "number", description: "Line offset to start reading from" },
        limit: { type: "number", description: "Maximum number of lines to read" }
      },
      required: ["file_path"]
    }
  },
  {
    name: "Write",
    description: "Writes content to a file, creating it if it doesn't exist.",
    input_schema: {
      type: "object",
      properties: {
        file_path: { type: "string", description: "The path of the file to write" },
        content: { type: "string", description: "The content to write to the file" }
      },
      required: ["file_path", "content"]
    }
  },
  {
    name: "Edit",
    description: "Makes a targeted edit to a file by replacing an exact string match.",
    input_schema: {
      type: "object",
      properties: {
        file_path: { type: "string", description: "The path of the file to edit" },
        old_string: { type: "string", description: "The exact string to replace" },
        new_string: { type: "string", description: "The replacement string" }
      },
      required: ["file_path", "old_string", "new_string"]
    }
  },
  {
    name: "MultiEdit",
    description: "Makes multiple targeted edits to a single file.",
    input_schema: {
      type: "object",
      properties: {
        file_path: { type: "string", description: "The path of the file to edit" },
        edits: {
          type: "array",
          items: {
            type: "object",
            properties: {
              old_string: { type: "string" },
              new_string: { type: "string" }
            },
            required: ["old_string", "new_string"]
          }
        }
      },
      required: ["file_path", "edits"]
    }
  },
  {
    name: "Glob",
    description: "Finds files matching a glob pattern.",
    input_schema: {
      type: "object",
      properties: {
        pattern: { type: "string", description: "Glob pattern to match files" },
        path: { type: "string", description: "Directory to search in" }
      },
      required: ["pattern"]
    }
  },
  {
    name: "Grep",
    description: "Searches for a pattern in files.",
    input_schema: {
      type: "object",
      properties: {
        pattern: { type: "string", description: "Regex pattern to search for" },
        path: { type: "string", description: "Directory or file to search in" },
        include: { type: "string", description: "File glob pattern to include" }
      },
      required: ["pattern"]
    }
  },
  {
    name: "LS",
    description: "Lists files and directories.",
    input_schema: {
      type: "object",
      properties: {
        path: { type: "string", description: "The path to list" }
      },
      required: ["path"]
    }
  },
  {
    name: "Task",
    description: "Launches a sub-agent to handle a complex task.",
    input_schema: {
      type: "object",
      properties: {
        description: { type: "string", description: "Task description for the sub-agent" },
        prompt: { type: "string", description: "The prompt for the task" }
      },
      required: ["description", "prompt"]
    }
  }
];

// ═══════════════════════════════════════════════════════════════════
// SYSTEM PROMPT TEMPLATES (realistic Claude Code prompts)
// ═══════════════════════════════════════════════════════════════════

const SYSTEM_PROMPT_PREFIX = `You are Claude Code, Anthropic's official CLI for Claude. You are an interactive CLI tool that helps users with software engineering tasks. Use the instructions below and the tools available to you to assist the user.

IMPORTANT: You should be conversational but concise. Avoid unnecessary preamble or filler. Get to the point quickly while being helpful.

# Memory
If the current working directory has a file called CLAUDE.md, it will be automatically loaded. If there is a ~/.claude/CLAUDE.md file, it will also be loaded.

# Tone and style
You should be concise, direct, and to the point. Avoid unnecessary filler words or phrases. Be conversational but professional. Use technical language when appropriate.`;

// ═══════════════════════════════════════════════════════════════════
// STATE
// ═══════════════════════════════════════════════════════════════════

const state = {
  requestTimestamps: [],
  hourlyCount: 0,
  hourlyReset: Date.now() + 3600000,
  dailyCount: 0,
  dailyReset: Date.now() + 86400000,
  
  // Session simulation
  currentBurstCount: 0,
  currentBurstTarget: randomInt(...CONFIG.sessions.burstSize),
  inBreak: false,
  breakUntil: 0,
  sessionStart: Date.now(),
  sessionTarget: randomInt(...CONFIG.sessions.duration),
  isFirstRequest: true,
  
  // Identity (pinned per session, like real user)
  currentVersion: weightedPick(CONFIG.identity.versions),
  currentPlatform: CONFIG.identity.platforms[0],
  sessionId: generateSessionId(),
  
  // Conversation tracking (for realistic patterns)
  turnCount: 0,
  lastRequestTime: 0,
};

// ═══════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════

function randomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function randomFloat(min, max) {
  return Math.random() * (max - min) + min;
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function weightedPick(items) {
  const total = items.reduce((sum, i) => sum + i.weight, 0);
  let r = Math.random() * total;
  for (const item of items) {
    r -= item.weight;
    if (r <= 0) return item.v;
  }
  return items[0].v;
}

function generateSessionId() {
  const chars = 'abcdef0123456789';
  let id = '';
  for (let i = 0; i < 32; i++) id += chars[Math.floor(Math.random() * chars.length)];
  return id;
}

function isQuietHours() {
  const h = new Date().getUTCHours();
  const { startUTC, endUTC } = CONFIG.quietHours;
  return startUTC > endUTC ? (h >= startUTC || h < endUTC) : (h >= startUTC && h < endUTC);
}

// ═══════════════════════════════════════════════════════════════════
// TIMING ENGINE
// ═══════════════════════════════════════════════════════════════════

function getHumanDelay() {
  // First request of a session? Simulate opening terminal
  if (state.isFirstRequest) {
    state.isFirstRequest = false;
    return randomInt(...CONFIG.delays.firstRequestDelay);
  }
  
  const base = randomFloat(CONFIG.delays.min, CONFIG.delays.max);
  
  // Coffee break (rare long pause)
  if (Math.random() < CONFIG.delays.coffeeChance) {
    return base + randomInt(...CONFIG.delays.coffeeExtra);
  }
  // Thinking pause (reading code output)
  if (Math.random() < CONFIG.delays.thinkingChance) {
    return base + randomInt(...CONFIG.delays.thinkingExtra);
  }
  
  return base;
}

function maybeSessionRotation() {
  const now = Date.now();
  
  // Session expired → take a break
  if (now - state.sessionStart > state.sessionTarget) {
    state.inBreak = true;
    state.breakUntil = now + randomInt(...CONFIG.sessions.breakTime);
    
    // Reset session
    state.sessionStart = state.breakUntil;
    state.sessionTarget = randomInt(...CONFIG.sessions.duration);
    state.currentBurstCount = 0;
    state.currentBurstTarget = randomInt(...CONFIG.sessions.burstSize);
    state.turnCount = 0;
    state.isFirstRequest = true;
    state.sessionId = generateSessionId();
    
    // Maybe update version between sessions (auto-update)
    if (Math.random() < 0.08) {
      state.currentVersion = weightedPick(CONFIG.identity.versions);
    }
    // Rotate platform hint occasionally
    if (Math.random() < 0.15) {
      state.currentPlatform = CONFIG.identity.platforms[randomInt(0, CONFIG.identity.platforms.length - 1)];
    }
  }
  
  // In break?
  if (state.inBreak && now < state.breakUntil) {
    return state.breakUntil - now;
  }
  state.inBreak = false;
  
  // Burst pattern: code → read output → code → read → ... → long pause
  state.currentBurstCount++;
  if (state.currentBurstCount >= state.currentBurstTarget) {
    state.currentBurstCount = 0;
    state.currentBurstTarget = randomInt(...CONFIG.sessions.burstSize);
    return randomInt(...CONFIG.sessions.burstPause);
  }
  
  return 0;
}

// ═══════════════════════════════════════════════════════════════════
// RATE LIMITER
// ═══════════════════════════════════════════════════════════════════

function checkRateLimit() {
  const now = Date.now();
  
  // Clean old timestamps
  state.requestTimestamps = state.requestTimestamps.filter(t => now - t < 60000);
  
  // Per-minute
  if (state.requestTimestamps.length >= CONFIG.rates.perMinute) {
    const wait = state.requestTimestamps[0] + 60000 - now + randomInt(500, 3000);
    return { ok: false, waitMs: wait, reason: "per-minute limit" };
  }
  
  // Reset counters
  if (now > state.hourlyReset) { state.hourlyCount = 0; state.hourlyReset = now + 3600000; }
  if (now > state.dailyReset) { state.dailyCount = 0; state.dailyReset = now + 86400000; }
  
  // Quiet hours stricter limit
  const hourlyLimit = isQuietHours() ? CONFIG.quietHours.maxPerHour : CONFIG.rates.perHour;
  
  if (state.hourlyCount >= hourlyLimit) {
    return { ok: false, waitMs: state.hourlyReset - now + randomInt(1000, 5000), reason: "hourly limit" };
  }
  if (state.dailyCount >= CONFIG.rates.perDay) {
    return { ok: false, waitMs: state.dailyReset - now, reason: "daily limit" };
  }
  
  return { ok: true, waitMs: 0 };
}

function recordRequest() {
  state.requestTimestamps.push(Date.now());
  state.hourlyCount++;
  state.dailyCount++;
  state.turnCount++;
  state.lastRequestTime = Date.now();
}

// ═══════════════════════════════════════════════════════════════════
// REQUEST TRANSFORMATION (the stealth layer)
// ═══════════════════════════════════════════════════════════════════

/**
 * Transform the request body to look like authentic Claude Code traffic.
 * - Injects Claude Code tool definitions
 * - Rewrites system prompt to match Claude Code's format
 * - Normalizes conversation structure
 */
export function transformRequest(bodyStr) {
  let body;
  try {
    body = JSON.parse(bodyStr);
  } catch {
    return bodyStr;
  }
  
  // 1. Inject Claude Code tools if not present
  if (!body.tools || body.tools.length === 0) {
    body.tools = CLAUDE_CODE_TOOLS;
  }
  
  // 2. Rewrite system prompt to match Claude Code format
  body.system = buildSystemPrompt(body.system);
  
  // 3. Add metadata that Claude Code sends
  if (!body.metadata) body.metadata = {};
  // Claude Code doesn't send extensive metadata, keep it minimal
  
  // 4. Ensure streaming matches Claude Code behavior (usually streaming)
  // Don't override if explicitly set
  
  return JSON.stringify(body);
}

/**
 * Build a system prompt that looks exactly like Claude Code's
 */
function buildSystemPrompt(existingSystem) {
  const blocks = [];
  
  // First block: Claude Code identity (always present, cached)
  blocks.push({
    type: "text",
    text: SYSTEM_PROMPT_PREFIX,
    cache_control: { type: "ephemeral" },
  });
  
  // Second block: project context / CLAUDE.md content
  // Wrap the original system prompt as if it's CLAUDE.md content
  let originalText = "";
  if (typeof existingSystem === "string") {
    // Strip the basic "You are Claude Code" prefix if already there
    originalText = existingSystem.replace(/^You are Claude Code, Anthropic's official CLI for Claude\.\s*/i, "");
  } else if (Array.isArray(existingSystem)) {
    // Extract text from blocks, skip any that are just the prefix
    for (const block of existingSystem) {
      if (block.type === "text" && !block.text.startsWith("You are Claude Code")) {
        originalText += block.text + "\n";
      }
    }
  }
  
  if (originalText.trim()) {
    blocks.push({
      type: "text",
      text: originalText.trim(),
      cache_control: { type: "ephemeral" },
    });
  }
  
  return blocks;
}

// ═══════════════════════════════════════════════════════════════════
// HEADER GENERATION
// ═══════════════════════════════════════════════════════════════════

/**
 * Generate headers that exactly match Claude Code CLI
 */
export function getHeaders() {
  return {
    "user-agent": `claude-cli/${state.currentVersion} ${state.currentPlatform}`,
    "x-app": "cli",
    "anthropic-dangerous-direct-browser-access": "true",
    "anthropic-beta": CONFIG.betaFeatures.join(","),
  };
}

// ═══════════════════════════════════════════════════════════════════
// MAIN GATE (called before every proxied request)
// ═══════════════════════════════════════════════════════════════════

/**
 * Anti-ban gate. Call before forwarding each request.
 * Returns: { proceed: bool, waitMs: number, headers: object, reason?: string }
 */
export async function antiBanGate() {
  // 1. Rate limit check
  const rate = checkRateLimit();
  if (!rate.ok) {
    return {
      proceed: false,
      waitMs: rate.waitMs,
      reason: `Rate limited (${rate.reason}). Retry after ${Math.ceil(rate.waitMs / 1000)}s`,
      headers: {},
    };
  }
  
  // 2. Session rotation (may trigger break)
  const sessionDelay = maybeSessionRotation();
  if (sessionDelay > 60000) {
    return {
      proceed: false,
      waitMs: sessionDelay,
      reason: `Session break (${Math.ceil(sessionDelay / 1000)}s). Simulating human pattern.`,
      headers: {},
    };
  } else if (sessionDelay > 0) {
    await sleep(Math.min(sessionDelay, 30000)); // Cap inline wait at 30s
  }
  
  // 3. Human-like thinking delay
  const delay = getHumanDelay();
  await sleep(delay);
  
  // 4. Record
  recordRequest();
  
  // 5. Return with stealth headers
  return {
    proceed: true,
    waitMs: 0,
    headers: getHeaders(),
  };
}

// ═══════════════════════════════════════════════════════════════════
// STATS (for /health endpoint)
// ═══════════════════════════════════════════════════════════════════

export function getStats() {
  return {
    requestsLastMinute: state.requestTimestamps.filter(t => Date.now() - t < 60000).length,
    requestsThisHour: state.hourlyCount,
    requestsToday: state.dailyCount,
    isQuietHours: isQuietHours(),
    inSessionBreak: state.inBreak,
    sessionTurns: state.turnCount,
    currentVersion: state.currentVersion,
    currentPlatform: state.currentPlatform,
    burstProgress: `${state.currentBurstCount}/${state.currentBurstTarget}`,
    toolsInjected: true,
    promptRewritten: true,
  };
}

export default { antiBanGate, getHeaders, getStats, transformRequest };
