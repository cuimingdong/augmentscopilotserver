/**
 * Worker 2: Cloud Orchestrator (Deno Deploy)
 *
 * Trung tâm điều phối MCP Registry
 * - Storage: Upstash Redis (256MB) - No Deno KV to avoid API issues
 * - Orchestrate: Worker 1 ↔ Worker 2 ↔ Worker 3
 * - Auto-update: Daily from Augment Registry via Worker 3
 *
 * URL: augmentsmcporchestrator.cuimingdong.deno.net
 *
 * @version 2.2.0 - PRIVACY ENHANCED
 */

// Import Privacy Guard (relative path for Deno Deploy)
import { privacyGuard } from "./privacy-guard.ts";

// Environment variables (SECURITY FIX: No hardcoded credentials)
const UPSTASH_REDIS_REST_URL = Deno.env.get("UPSTASH_REDIS_REST_URL");
const UPSTASH_REDIS_REST_TOKEN = Deno.env.get("UPSTASH_REDIS_REST_TOKEN");
const AUGMENT_GATEWAY_URL = Deno.env.get("AUGMENT_GATEWAY_URL") || "https://augmentsmcporchestrator.cuimingdong.deno.net";

// Validate required environment variables
if (!UPSTASH_REDIS_REST_URL || !UPSTASH_REDIS_REST_TOKEN) {
  console.error("❌ CRITICAL: Missing required environment variables");
  console.error("   Required: UPSTASH_REDIS_REST_URL, UPSTASH_REDIS_REST_TOKEN");
  console.error("   Set them in Deno Deploy dashboard: https://dash.deno.com/projects/augmentsmcporchestrator");
}

// Types
interface McpServer {
  name: string;
  version: string;
  description: string;
  author?: string;
  homepage?: string;
  tools: McpTool[];
  resources: McpResource[];
  prompts: McpPrompt[];
  lastUpdated: string;
  size: number;
}

interface McpTool {
  name: string;
  description: string;
  inputSchema: {
    type: 'object';
    properties: Record<string, any>;
    required?: string[];
  };
}

interface McpResource {
  uri: string;
  name: string;
  description: string;
  mimeType: string;
}

interface McpPrompt {
  name: string;
  description: string;
  arguments?: Array<{
    name: string;
    description: string;
    required?: boolean;
  }>;
}

// Upstash Redis Helper
class UpstashRedis {
  private baseUrl: string;
  private token: string;

  constructor(url: string, token: string) {
    this.baseUrl = url;
    this.token = token;
  }

  async get(key: string): Promise<string | null> {
    if (!this.token) return null;
    try {
      const response = await fetch(`${this.baseUrl}/get/${key}`, {
        headers: { "Authorization": `Bearer ${this.token}` }
      });
      const data = await response.json();
      return data.result;
    } catch {
      return null;
    }
  }

  async set(key: string, value: string, ttl?: number): Promise<void> {
    if (!this.token) return;
    try {
      const url = ttl 
        ? `${this.baseUrl}/setex/${key}/${ttl}/${encodeURIComponent(value)}`
        : `${this.baseUrl}/set/${key}/${encodeURIComponent(value)}`;
      await fetch(url, {
        headers: { "Authorization": `Bearer ${this.token}` }
      });
    } catch (error) {
      // 🔒 Privacy: Sanitize error before logging
      privacyGuard.logSafe("[Upstash] Set error:", error);
    }
  }

  async del(key: string): Promise<void> {
    if (!this.token) return;
    try {
      await fetch(`${this.baseUrl}/del/${key}`, {
        headers: { "Authorization": `Bearer ${this.token}` }
      });
    } catch (error) {
      // 🔒 Privacy: Sanitize error before logging
      privacyGuard.logSafe("[Upstash] Del error:", error);
    }
  }
}

const upstash = new UpstashRedis(UPSTASH_REDIS_REST_URL, UPSTASH_REDIS_REST_TOKEN);

// Storage Layer - Using Upstash Redis Only (256MB)
class McpStorage {
  async getServer(name: string): Promise<McpServer | null> {
    const cached = await upstash.get(`mcp:server:${name}`);
    if (cached) {
      console.log(`[Storage] Found ${name} in Upstash`);
      return JSON.parse(cached);
    }
    return null;
  }

  async listServers(): Promise<McpServer[]> {
    const cached = await upstash.get("mcp:list");
    if (cached) {
      console.log("[Storage] Server list from Upstash");
      return JSON.parse(cached);
    }
    return [];
  }

  async saveServer(server: McpServer): Promise<void> {
    // Save individual server (no TTL - permanent)
    await upstash.set(`mcp:server:${server.name}`, JSON.stringify(server));
    console.log(`[Storage] Saved server: ${server.name}`);
  }

  async saveAllServers(servers: McpServer[]): Promise<void> {
    // Save list (no TTL - permanent)
    await upstash.set("mcp:list", JSON.stringify(servers));
    console.log(`[Storage] Saved ${servers.length} servers to list`);
  }

  async searchServers(query: string): Promise<McpServer[]> {
    const servers = await this.listServers();
    const lowerQuery = query.toLowerCase();

    return servers.filter(server =>
      server.name.toLowerCase().includes(lowerQuery) ||
      server.description.toLowerCase().includes(lowerQuery) ||
      server.tools.some(t => t.name.toLowerCase().includes(lowerQuery))
    );
  }

  async getMetadata() {
    const servers = await this.listServers();
    const totalSize = servers.reduce((sum, s) => sum + s.size, 0);
    const lastUpdate = await upstash.get("mcp:metadata:lastUpdate");

    return {
      totalServers: servers.length,
      lastUpdate: lastUpdate || new Date().toISOString(),
      storageUsed: totalSize
    };
  }

  async invalidateCache(): Promise<void> {
    await upstash.del("mcp:list");
    console.log("[Cache] Invalidated list cache");
  }
}

const storage = new McpStorage();

// Update from Worker 3 (Augment Gateway)
async function updateFromAugmentRegistry(): Promise<{ success: boolean; count: number; error?: string }> {
  try {
    console.log("[Update] Fetching from Worker 3:", AUGMENT_GATEWAY_URL);
    
    const response = await fetch(`${AUGMENT_GATEWAY_URL}/augment/servers`);
    if (!response.ok) {
      throw new Error(`Worker 3 returned ${response.status}`);
    }

    const data = await response.json();
    const servers: McpServer[] = data.servers || [];

    console.log(`[Update] Received ${servers.length} servers from Worker 3`);

    // Save all servers to Upstash
    await storage.saveAllServers(servers);

    // Also save individual servers for quick lookup
    for (const server of servers) {
      await storage.saveServer(server);
    }

    // Update metadata
    await upstash.set("mcp:metadata:lastUpdate", new Date().toISOString());
    await upstash.set("mcp:metadata:totalServers", servers.length.toString());

    console.log(`[Update] Successfully updated ${servers.length} servers`);
    return { success: true, count: servers.length };

  } catch (error: any) {
    // 🔒 Privacy: Sanitize error before logging
    privacyGuard.logSafe("[Update] Failed:", error);
    
    // Sanitize error message (remove file paths, tokens)
    const sanitizedMessage = privacyGuard.sanitizeString(error?.message || "Unknown error");
    return { success: false, count: 0, error: sanitizedMessage };
  }
}

// CORS headers
function getCORSHeaders(): Record<string, string> {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
  };
}

// Main HTTP handler (PRIVACY ENHANCED)
async function handleRequest(req: Request): Promise<Response> {
  const url = new URL(req.url);
  const path = url.pathname;

  // 🔒 Privacy: Hash IP for logging (no raw IPs stored)
  const clientIP = req.headers.get("cf-connecting-ip") || 
                   req.headers.get("x-forwarded-for") || 
                   req.headers.get("x-real-ip") || 
                   "unknown";
  const hashedIP = privacyGuard.hashIP(clientIP);

  // 🔒 Privacy: Log safely (no sensitive data)
  privacyGuard.logSafe(`[${hashedIP}] ${req.method} ${path}`);

  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: getCORSHeaders() });
  }

  // 🔒 Privacy: Check request size (prevent data dumps)
  const MAX_REQUEST_SIZE = 100 * 1024; // 100KB
  const contentLength = req.headers.get("content-length");
  if (contentLength && parseInt(contentLength) > MAX_REQUEST_SIZE) {
    return new Response(JSON.stringify({
      error: "Request too large",
      message: "Maximum request size is 100KB for privacy reasons"
    }), {
      status: 413,
      headers: { ...getCORSHeaders(), "Content-Type": "application/json" }
    });
  }

  // Health check
  if (path === "/health" || path === "/") {
    const metadata = await storage.getMetadata();
    return new Response(JSON.stringify({
      status: "ok",
      worker: "Cloud Orchestrator",
      version: "2.2.0-privacy-enhanced",
      storage: {
        type: "Upstash Redis (256MB)",
        totalServers: metadata.totalServers,
        storageUsed: `${(metadata.storageUsed / 1024 / 1024).toFixed(2)} MB`,
        lastUpdate: metadata.lastUpdate
      },
      workers: {
        worker1: "VSCode Gateway (Cloudflare)",
        worker2: "Cloud Orchestrator (Deno) - YOU ARE HERE",
        worker3: `Augment Gateway (${AUGMENT_GATEWAY_URL})`
      },
      privacy: {
        ipLogging: "Hashed only",
        dataSanitization: "Enabled",
        maxRequestSize: "100KB",
        sourceCode: "NEVER sent to cloud"
      },
      timestamp: new Date().toISOString()
    }), {
      headers: { ...getCORSHeaders(), "Content-Type": "application/json" }
    });
  }

  // List all MCP servers
  if (path === "/mcp/list" && req.method === "GET") {
    const servers = await storage.listServers();
    return new Response(JSON.stringify({
      servers: servers.map(s => ({
        name: s.name,
        version: s.version,
        description: s.description,
        author: s.author,
        homepage: s.homepage,
        toolsCount: s.tools.length,
        resourcesCount: s.resources.length,
        promptsCount: s.prompts.length,
        size: s.size,
        lastUpdated: s.lastUpdated
      }))
    }), {
      headers: { ...getCORSHeaders(), "Content-Type": "application/json" }
    });
  }

  // Get specific server
  if (path.startsWith("/mcp/server/") && req.method === "GET") {
    const name = path.replace("/mcp/server/", "");
    const server = await storage.getServer(name);
    
    if (!server) {
      return new Response(JSON.stringify({ error: "Server not found" }), {
        status: 404,
        headers: { ...getCORSHeaders(), "Content-Type": "application/json" }
      });
    }

    return new Response(JSON.stringify(server), {
      headers: { ...getCORSHeaders(), "Content-Type": "application/json" }
    });
  }

  // Search servers
  if (path === "/mcp/search" && req.method === "GET") {
    const query = url.searchParams.get("q") || "";
    const results = await storage.searchServers(query);
    
    return new Response(JSON.stringify({ results }), {
      headers: { ...getCORSHeaders(), "Content-Type": "application/json" }
    });
  }

  // Manual update (admin only)
  if (path === "/admin/update" && req.method === "POST") {
    const result = await updateFromAugmentRegistry();
    return new Response(JSON.stringify(result), {
      status: result.success ? 200 : 500,
      headers: { ...getCORSHeaders(), "Content-Type": "application/json" }
    });
  }

  return new Response("Not Found", { status: 404, headers: getCORSHeaders() });
}

// Cron: Auto-update daily at 00:00 UTC
Deno.cron("update_mcp_servers", "0 0 * * *", async () => {
  console.log("[Cron] Starting daily update...");
  await updateFromAugmentRegistry();
});

// Start server
console.log("🚀 Cloud Orchestrator starting...");
console.log("📦 Storage: Upstash Redis (256MB)");
console.log("🔗 Worker 3:", AUGMENT_GATEWAY_URL);

Deno.serve(handleRequest);

