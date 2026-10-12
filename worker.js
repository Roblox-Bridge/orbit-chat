const COOKIE = "orbit_session";
const SESSION_DAYS = 30;
const USERNAME_RE = /^[a-zA-Z0-9_]{3,20}$/;

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...extra,
    },
  });
}

function secureHeaders(response) {
  const headers = new Headers(response.headers);
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
  headers.set("X-Frame-Options", "DENY");
  headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  headers.set(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self' ws: wss:; img-src 'self' data: blob:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
  );
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

function cookieValue(request, name) {
  const raw = request.headers.get("Cookie") || "";
  for (const part of raw.split(";")) {
    const index = part.indexOf("=");
    if (index < 0) continue;
    if (part.slice(0, index).trim() === name) {
      return part.slice(index + 1).trim();
    }
  }
  return null;
}

function hex(bytes) {
  return Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
}

function unhex(value) {
  return new Uint8Array(
    value.match(/.{2}/g).map(part => parseInt(part, 16))
  );
}

function randomToken(size = 32) {
  const bytes = crypto.getRandomValues(new Uint8Array(size));
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

async function sha256(value) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value)
  );
  return hex(new Uint8Array(digest));
}

async function passwordHash(password, saltHex) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const result = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: unhex(saltHex),
      iterations: 100000,
      hash: "SHA-256",
    },
    key,
    256
  );

  return hex(new Uint8Array(result));
}

async function readJson(request) {
  const type = request.headers.get("Content-Type") || "";
  if (!type.includes("application/json")) {
    throw new Error("JSON_REQUIRED");
  }

  const length = Number(request.headers.get("Content-Length") || 0);
  if (length > 20000) throw new Error("BODY_TOO_LARGE");

  return request.json();
}

function setSessionCookie(token) {
  return `${COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_DAYS * 86400}`;
}

function clearSessionCookie() {
  return `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

async function getSession(request, env) {
  const token = cookieValue(request, COOKIE);
  if (!token || token.length > 200) return null;

  const tokenHash = await sha256(token);
  return env.DB.prepare(`
    SELECT u.id, u.username, u.display_name
    FROM sessions s
    JOIN users u ON u.id = s.user_id
    WHERE s.token_hash = ? AND s.expires_at > ?
  `).bind(tokenHash, Date.now()).first();
}

async function createSession(userId, env) {
  const token = randomToken();
  const expires = Date.now() + SESSION_DAYS * 86400000;

  await env.DB.prepare(`
    INSERT INTO sessions (token_hash, user_id, expires_at, created_at)
    VALUES (?, ?, ?, ?)
  `).bind(
    await sha256(token),
    userId,
    expires,
    Date.now()
  ).run();

  return token;
}

async function requireSession(request, env) {
  const user = await getSession(request, env);
  if (!user) return { error: json({ error: "Please log in again." }, 401) };
  return { user };
}

async function isParticipant(env, conversationId, userId) {
  return !!await env.DB.prepare(`
    SELECT 1 FROM participants
    WHERE conversation_id = ? AND user_id = ?
  `).bind(conversationId, userId).first();
}

async function api(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204 });
  }

  // All write requests must come from this same origin.
  if (["POST", "PUT", "PATCH", "DELETE"].includes(request.method)) {
    const origin = request.headers.get("Origin");
    if (origin && new URL(origin).host !== url.host) {
      return json({ error: "Cross-origin request rejected." }, 403);
    }
  }

  if (path === "/api/health" && request.method === "GET") {
    return json({ ok: true, service: "Orbit Chat" });
  }

  if (path === "/api/register" && request.method === "POST") {
    let body;
    try {
      body = await readJson(request);
    } catch {
      return json({ error: "Invalid request body." }, 400);
    }

    const username = String(body.username || "").trim().toLowerCase();
    const displayName = String(body.displayName || username).trim().slice(0, 40);
    const password = String(body.password || "");

    if (!USERNAME_RE.test(username)) {
      return json({
        error: "Username must be 3–20 characters: letters, numbers or underscore.",
      }, 400);
    }

    if (password.length < 10 || password.length > 128) {
      return json({ error: "Password must be 10–128 characters." }, 400);
    }

    if (!displayName) {
      return json({ error: "Please enter a display name." }, 400);
    }

    const existing = await env.DB.prepare(
      "SELECT id FROM users WHERE username = ?"
    ).bind(username).first();

    if (existing) {
      return json({ error: "That username is already taken." }, 409);
    }

    const id = crypto.randomUUID();
    const salt = hex(crypto.getRandomValues(new Uint8Array(16)));
    const hash = await passwordHash(password, salt);
    const now = Date.now();

    try {
      await env.DB.prepare(`
        INSERT INTO users
          (id, username, display_name, password_hash, password_salt, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
      `).bind(id, username, displayName, hash, salt, now).run();
    } catch {
      return json({ error: "Could not create account. Try another username." }, 409);
    }

    const token = await createSession(id, env);
    return json({
      user: { id, username, displayName },
    }, 201, { "Set-Cookie": setSessionCookie(token) });
  }

  if (path === "/api/login" && request.method === "POST") {
    let body;
    try {
      body = await readJson(request);
    } catch {
      return json({ error: "Invalid request body." }, 400);
    }

    const username = String(body.username || "").trim().toLowerCase();
    const password = String(body.password || "");

    if (username.length > 20 || password.length > 128) {
      return json({ error: "Invalid username or password." }, 400);
    }

    const user = await env.DB.prepare(`
      SELECT id, username, display_name, password_hash, password_salt
      FROM users WHERE username = ?
    `).bind(username).first();

    if (!user) {
      return json({ error: "Incorrect username or password." }, 401);
    }

    const actual = await passwordHash(password, user.password_salt);
    if (actual !== user.password_hash) {
      return json({ error: "Incorrect username or password." }, 401);
    }

    const token = await createSession(user.id, env);
    return json({
      user: {
        id: user.id,
        username: user.username,
        displayName: user.display_name,
      },
    }, 200, { "Set-Cookie": setSessionCookie(token) });
  }

  if (path === "/api/logout" && request.method === "POST") {
    const token = cookieValue(request, COOKIE);
    if (token) {
      await env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?")
        .bind(await sha256(token)).run();
    }

    return json({ ok: true }, 200, { "Set-Cookie": clearSessionCookie() });
  }

  if (path === "/api/me" && request.method === "GET") {
    const result = await requireSession(request, env);
    if (result.error) return result.error;

    return json({
      user: {
        id: result.user.id,
        username: result.user.username,
        displayName: result.user.display_name,
      },
    });
  }

  if (path === "/api/users" && request.method === "GET") {
    const result = await requireSession(request, env);
    if (result.error) return result.error;

    const q = String(url.searchParams.get("q") || "")
      .trim().toLowerCase().slice(0, 20);

    if (q.length < 2) return json({ users: [] });

    const found = await env.DB.prepare(`
      SELECT id, username, display_name
      FROM users
      WHERE username LIKE ? AND id != ?
      ORDER BY username LIMIT 15
    `).bind(`${q.replace(/[%_\\]/g, "\\$&")}%`, result.user.id).all();

    return json({
      users: (found.results || []).map(u => ({
        id: u.id,
        username: u.username,
        displayName: u.display_name,
      })),
    });
  }

  if (path === "/api/conversations" && request.method === "GET") {
    const result = await requireSession(request, env);
    if (result.error) return result.error;

    const found = await env.DB.prepare(`
      SELECT c.id, c.created_at,
        u.id AS other_id,
        u.username AS other_username,
        u.display_name AS other_display_name
      FROM conversations c
      JOIN participants me
        ON me.conversation_id = c.id AND me.user_id = ?
      JOIN participants other
        ON other.conversation_id = c.id AND other.user_id != ?
      JOIN users u ON u.id = other.user_id
      ORDER BY c.created_at DESC
      LIMIT 100
    `).bind(result.user.id, result.user.id).all();

    return json({
      conversations: (found.results || []).map(c => ({
        id: c.id,
        createdAt: c.created_at,
        otherUser: {
          id: c.other_id,
          username: c.other_username,
          displayName: c.other_display_name,
        },
      })),
    });
  }

  if (path === "/api/conversations" && request.method === "POST") {
    const result = await requireSession(request, env);
    if (result.error) return result.error;

    let body;
    try {
      body = await readJson(request);
    } catch {
      return json({ error: "Invalid request body." }, 400);
    }

    const username = String(body.username || "").trim().toLowerCase();
    if (!USERNAME_RE.test(username)) {
      return json({ error: "Enter a valid username." }, 400);
    }

    const other = await env.DB.prepare(`
      SELECT id, username, display_name
      FROM users WHERE username = ?
    `).bind(username).first();

    if (!other) return json({ error: "User not found." }, 404);
    if (other.id === result.user.id) {
      return json({ error: "You cannot start a chat with yourself." }, 400);
    }

    const existing = await env.DB.prepare(`
      SELECT c.id FROM conversations c
      JOIN participants p1 ON p1.conversation_id = c.id
      JOIN participants p2 ON p2.conversation_id = c.id
      WHERE p1.user_id = ? AND p2.user_id = ? AND c.kind = 'direct'
      LIMIT 1
    `).bind(result.user.id, other.id).first();

    if (existing) {
      return json({ conversation: {
        id: existing.id,
        otherUser: {
          id: other.id,
          username: other.username,
          displayName: other.display_name,
        },
      } });
    }

    const id = crypto.randomUUID();
    const now = Date.now();

    await env.DB.prepare(
      "INSERT INTO conversations (id, kind, created_at) VALUES (?, 'direct', ?)"
    ).bind(id, now).run();

    await env.DB.prepare(`
      INSERT INTO participants (conversation_id, user_id, joined_at)
      VALUES (?, ?, ?), (?, ?, ?)
    `).bind(
      id, result.user.id, now,
      id, other.id, now
    ).run();

    return json({ conversation: {
      id,
      otherUser: {
        id: other.id,
        username: other.username,
        displayName: other.display_name,
      },
    } }, 201);
  }

  if (path === "/api/history" && request.method === "GET") {
    const result = await requireSession(request, env);
    if (result.error) return result.error;

    const id = url.searchParams.get("conversationId") || "";
    if (!/^[0-9a-f-]{36}$/i.test(id)) {
      return json({ error: "Invalid conversation." }, 400);
    }

    if (!await isParticipant(env, id, result.user.id)) {
      return json({ error: "Conversation not found." }, 404);
    }

    const room = env.CHAT_ROOM.getByName(id);
    const response = await room.fetch("https://room.internal/history");
    return new Response(response.body, {
      status: response.status,
      headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
    });
  }

  if (path === "/api/ws" && request.method === "GET") {
    const result = await requireSession(request, env);
    if (result.error) return result.error;

    if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
      return json({ error: "WebSocket upgrade required." }, 426);
    }

    const id = url.searchParams.get("conversationId") || "";
    if (!/^[0-9a-f-]{36}$/i.test(id)) {
      return json({ error: "Invalid conversation." }, 400);
    }

    if (!await isParticipant(env, id, result.user.id)) {
      return json({ error: "Conversation not found." }, 404);
    }

    const room = env.CHAT_ROOM.getByName(id);
    const target = new URL("https://room.internal/websocket");
    target.searchParams.set("uid", result.user.id);
    target.searchParams.set("username", result.user.username);
    target.searchParams.set("displayName", result.user.display_name);

    return room.fetch(new Request(target, request));
  }

  return json({ error: "Not found." }, 404);
}

export class ChatRoom {
  constructor(ctx, env) {
    this.ctx = ctx;
    this.env = env;

    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS messages (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        username TEXT NOT NULL,
        display_name TEXT NOT NULL,
        content TEXT NOT NULL,
        created_at INTEGER NOT NULL
      )
    `);

    this.ctx.storage.setWebSocketAutoResponse(
      new WebSocketRequestResponsePair("ping", "pong")
    );
  }

  async fetch(request) {
    const url = new URL(request.url);

    if (url.pathname === "/history") {
      const rows = this.ctx.storage.sql.exec(`
        SELECT id, user_id AS userId, username,
          display_name AS displayName, content, created_at AS createdAt
        FROM messages
        ORDER BY created_at DESC LIMIT 100
      `).toArray().reverse();

      return json({ messages: rows });
    }

    if (url.pathname !== "/websocket" ||
        request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
      return new Response("Not found", { status: 404 });
    }

    const uid = url.searchParams.get("uid");
    const username = url.searchParams.get("username");
    const displayName = url.searchParams.get("displayName");

    if (!uid || !username || !displayName) {
      return new Response("Unauthorized", { status: 401 });
    }

    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];

    this.ctx.acceptWebSocket(server);
    server.serializeAttachment({ uid, username, displayName });

    return new Response(null, { status: 101, webSocket: client });
  }

  async webSocketMessage(ws, raw) {
    const user = ws.deserializeAttachment();
    if (!user) return;

    let packet;
    try {
      packet = JSON.parse(typeof raw === "string" ? raw : "");
    } catch {
      return;
    }

    if (packet.type !== "message") return;
    if (typeof packet.content !== "string") return;

    const content = packet.content.trim();
    if (!content || content.length > 4000) return;

    const message = {
      id: crypto.randomUUID(),
      userId: user.uid,
      username: user.username,
      displayName: user.displayName,
      content,
      createdAt: Date.now(),
    };

    this.ctx.storage.sql.exec(`
      INSERT INTO messages
        (id, user_id, username, display_name, content, created_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `,
      message.id,
      message.userId,
      message.username,
      message.displayName,
      message.content,
      message.createdAt
    );

    const outgoing = JSON.stringify({
      type: "message",
      message,
    });

    for (const socket of this.ctx.getWebSockets()) {
      try {
        socket.send(outgoing);
      } catch {
        // A disconnected client should not block delivery to other clients.
      }
    }
  }

  webSocketClose(ws) {
    try {
      ws.close();
    } catch {}
  }

  webSocketError(ws) {
    try {
      ws.close(1011, "Connection error");
    } catch {}
  }
}

export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      let response;

      if (url.pathname.startsWith("/api/")) {
        response = await api(request, env);
      } else if (env.ASSETS) {
        response = await env.ASSETS.fetch(request);
      } else {
        response = new Response("Orbit Chat assets are not configured.", {
          status: 503,
        });
      }

      return secureHeaders(response);
    } catch (error) {
      // Keep internal details out of responses.
      return json({ error: "Server error. Please try again." }, 500);
    }
  },
};
