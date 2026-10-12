
const COOKIE = "orbit_session";
const SESSION_DAYS = 30;
const USERNAME_RE = /^[a-zA-Z0-9_]{3,20}$/;
const PASSWORD_MIN = 10;
const PASSWORD_MAX = 128;
const MESSAGE_MAX = 4000;

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
  // IMPORTANT: Do not wrap or reconstruct a WebSocket upgrade response.
  if (response.status === 101) {
    return response;
  }

  const headers = new Headers(response.headers);

  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
  headers.set("X-Frame-Options", "DENY");
  headers.set(
    "Permissions-Policy",
    "camera=(), microphone=(), geolocation=()"
  );

  headers.set(
    "Content-Security-Policy",
    "default-src 'self'; " +
      "script-src 'self' 'unsafe-inline'; " +
      "style-src 'self' 'unsafe-inline'; " +
      "connect-src 'self' ws: wss:; " +
      "img-src 'self' data: blob:; " +
      "object-src 'none'; " +
      "base-uri 'self'; " +
      "frame-ancestors 'none'"
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
  return Array.from(bytes, byte =>
    byte.toString(16).padStart(2, "0")
  ).join("");
}

function unhex(value) {
  if (!/^(?:[a-f0-9]{2})+$/i.test(value)) {
    throw new Error("INVALID_HEX");
  }

  const bytes = new Uint8Array(value.length / 2);

  for (let i = 0; i < value.length; i += 2) {
    bytes[i / 2] = parseInt(value.slice(i, i + 2), 16);
  }

  return bytes;
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

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: unhex(saltHex),
      iterations: 100000,
      hash: "SHA-256",
    },
    key,
    256
  );

  return hex(new Uint8Array(bits));
}

function constantTimeEqual(a, b) {
  if (
    typeof a !== "string" ||
    typeof b !== "string" ||
    a.length !== b.length
  ) {
    return false;
  }

  let difference = 0;

  for (let i = 0; i < a.length; i++) {
    difference |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }

  return difference === 0;
}

function setSessionCookie(token) {
  return (
    `${COOKIE}=${token}; Path=/; HttpOnly; Secure; ` +
    `SameSite=Lax; Max-Age=${SESSION_DAYS * 86400}`
  );
}

function clearSessionCookie() {
  return (
    `${COOKIE}=; Path=/; HttpOnly; Secure; ` +
    "SameSite=Lax; Max-Age=0"
  );
}

async function readJson(request) {
  const contentType = request.headers.get("Content-Type") || "";

  if (!contentType.toLowerCase().includes("application/json")) {
    throw new Error("JSON_REQUIRED");
  }

  const length = Number(request.headers.get("Content-Length") || 0);

  if (length > 20000) {
    throw new Error("BODY_TOO_LARGE");
  }

  const text = await request.text();

  if (text.length > 20000) {
    throw new Error("BODY_TOO_LARGE");
  }

  try {
    const data = JSON.parse(text);

    if (!data || typeof data !== "object" || Array.isArray(data)) {
      throw new Error("INVALID_JSON");
    }

    return data;
  } catch {
    throw new Error("INVALID_JSON");
  }
}

function getText(value, maxLength) {
  if (typeof value !== "string") return "";
  return value.trim().slice(0, maxLength);
}

function isValidId(value) {
  return (
    typeof value === "string" &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(
      value
    )
  );
}

async function getSession(request, env) {
  const token = cookieValue(request, COOKIE);

  if (
    !token ||
    token.length > 100 ||
    !/^[A-Za-z0-9_-]+$/.test(token)
  ) {
    return null;
  }

  const tokenHash = await sha256(token);

  return env.DB.prepare(`
    SELECT u.id, u.username, u.display_name
    FROM sessions s
    JOIN users u ON u.id = s.user_id
    WHERE s.token_hash = ?
      AND s.expires_at > ?
  `).bind(tokenHash, Date.now()).first();
}

async function createSession(userId, env) {
  const token = randomToken();
  const now = Date.now();
  const expires = now + SESSION_DAYS * 86400000;
  const tokenHash = await sha256(token);

  await env.DB.prepare(`
    INSERT INTO sessions (
      token_hash,
      user_id,
      expires_at,
      created_at
    )
    VALUES (?, ?, ?, ?)
  `).bind(tokenHash, userId, expires, now).run();

  return token;
}

async function requireSession(request, env) {
  const user = await getSession(request, env);

  if (!user) {
    return {
      error: json({ error: "Please log in again." }, 401),
    };
  }

  return { user };
}

async function isParticipant(env, conversationId, userId) {
  const row = await env.DB.prepare(`
    SELECT 1
    FROM participants
    WHERE conversation_id = ?
      AND user_id = ?
  `).bind(conversationId, userId).first();

  return Boolean(row);
}

function publicUser(user) {
  return {
    id: user.id,
    username: user.username,
    displayName: user.display_name,
  };
}

async function handleRegister(request, env) {
  let body;

  try {
    body = await readJson(request);
  } catch (error) {
    return json({
      error: error.message === "BODY_TOO_LARGE"
        ? "Request is too large."
        : "Invalid request body.",
    }, error.message === "BODY_TOO_LARGE" ? 413 : 400);
  }

  const username = getText(body.username, 20).toLowerCase();
  const displayName = getText(body.displayName || username, 40);
  const password =
    typeof body.password === "string" ? body.password : "";

  if (!USERNAME_RE.test(username)) {
    return json({
      error: "Username must be 3–20 characters: letters, numbers or underscore.",
    }, 400);
  }

  if (
    password.length < PASSWORD_MIN ||
    password.length > PASSWORD_MAX
  ) {
    return json({
      error: "Password must be 10–128 characters.",
    }, 400);
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
      INSERT INTO users (
        id,
        username,
        display_name,
        password_hash,
        password_salt,
        created_at
      )
      VALUES (?, ?, ?, ?, ?, ?)
    `).bind(
      id,
      username,
      displayName,
      hash,
      salt,
      now
    ).run();
  } catch {
    // Also handles a concurrent registration of the same username.
    return json({
      error: "Could not create account. The username may already exist.",
    }, 409);
  }

  const token = await createSession(id, env);

  return json({
    user: {
      id,
      username,
      displayName,
    },
  }, 201, {
    "Set-Cookie": setSessionCookie(token),
  });
}

async function handleLogin(request, env) {
  let body;

  try {
    body = await readJson(request);
  } catch (error) {
    return json({
      error: error.message === "BODY_TOO_LARGE"
        ? "Request is too large."
        : "Invalid request body.",
    }, error.message === "BODY_TOO_LARGE" ? 413 : 400);
  }

  const username = getText(body.username, 20).toLowerCase();
  const password =
    typeof body.password === "string" ? body.password : "";

  if (
    !USERNAME_RE.test(username) ||
    password.length === 0 ||
    password.length > PASSWORD_MAX
  ) {
    return json({
      error: "Incorrect username or password.",
    }, 401);
  }

  const user = await env.DB.prepare(`
    SELECT
      id,
      username,
      display_name,
      password_hash,
      password_salt
    FROM users
    WHERE username = ?
  `).bind(username).first();

  if (!user) {
    return json({
      error: "Incorrect username or password.",
    }, 401);
  }

  const actual = await passwordHash(
    password,
    user.password_salt
  );

  if (!constantTimeEqual(actual, user.password_hash)) {
    return json({
      error: "Incorrect username or password.",
    }, 401);
  }

  const token = await createSession(user.id, env);

  return json({
    user: publicUser(user),
  }, 200, {
    "Set-Cookie": setSessionCookie(token),
  });
}

async function handleLogout(request, env) {
  const token = cookieValue(request, COOKIE);

  if (token && /^[A-Za-z0-9_-]{1,100}$/.test(token)) {
    await env.DB.prepare(`
      DELETE FROM sessions
      WHERE token_hash = ?
    `).bind(await sha256(token)).run();
  }

  return json({ ok: true }, 200, {
    "Set-Cookie": clearSessionCookie(),
  });
}

async function handleUserSearch(request, env) {
  const auth = await requireSession(request, env);

  if (auth.error) return auth.error;

  const url = new URL(request.url);
  const query = getText(url.searchParams.get("q"), 20).toLowerCase();

  if (query.length < 2) {
    return json({ users: [] });
  }

  const escaped = query.replace(/[\\%_]/g, "\\$&");

  const found = await env.DB.prepare(`
    SELECT id, username, display_name
    FROM users
    WHERE username LIKE ? ESCAPE '\\'
      AND id != ?
    ORDER BY username
    LIMIT 15
  `).bind(
    `${escaped}%`,
    auth.user.id
  ).all();

  return json({
    users: (found.results || []).map(publicUser),
  });
}

async function handleListConversations(request, env) {
  const auth = await requireSession(request, env);

  if (auth.error) return auth.error;

  const found = await env.DB.prepare(`
    SELECT
      c.id,
      c.created_at,
      u.id AS other_id,
      u.username AS other_username,
      u.display_name AS other_display_name
    FROM conversations c
    JOIN participants me
      ON me.conversation_id = c.id
     AND me.user_id = ?
    JOIN participants other
      ON other.conversation_id = c.id
     AND other.user_id != ?
    JOIN users u
      ON u.id = other.user_id
    ORDER BY c.created_at DESC
    LIMIT 100
  `).bind(
    auth.user.id,
    auth.user.id
  ).all();

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

async function handleCreateConversation(request, env) {
  const auth = await requireSession(request, env);

  if (auth.error) return auth.error;

  let body;

  try {
    body = await readJson(request);
  } catch (error) {
    return json({
      error: error.message === "BODY_TOO_LARGE"
        ? "Request is too large."
        : "Invalid request body.",
    }, error.message === "BODY_TOO_LARGE" ? 413 : 400);
  }

  const username = getText(body.username, 20).toLowerCase();

  if (!USERNAME_RE.test(username)) {
    return json({ error: "Enter a valid username." }, 400);
  }

  const other = await env.DB.prepare(`
    SELECT id, username, display_name
    FROM users
    WHERE username = ?
  `).bind(username).first();

  if (!other) {
    return json({ error: "User not found." }, 404);
  }

  if (other.id === auth.user.id) {
    return json({
      error: "You cannot start a chat with yourself.",
    }, 400);
  }

  const existing = await env.DB.prepare(`
    SELECT c.id
    FROM conversations c
    JOIN participants p1
      ON p1.conversation_id = c.id
    JOIN participants p2
      ON p2.conversation_id = c.id
    WHERE p1.user_id = ?
      AND p2.user_id = ?
      AND c.kind = 'direct'
    LIMIT 1
  `).bind(
    auth.user.id,
    other.id
  ).first();

  if (existing) {
    return json({
      conversation: {
        id: existing.id,
        otherUser: publicUser(other),
      },
    });
  }

  const id = crypto.randomUUID();
  const now = Date.now();

  // D1 batch commits these related inserts transactionally.
  await env.DB.batch([
    env.DB.prepare(`
      INSERT INTO conversations (id, kind, created_at)
      VALUES (?, 'direct', ?)
    `).bind(id, now),

    env.DB.prepare(`
      INSERT INTO participants (
        conversation_id,
        user_id,
        joined_at
      )
      VALUES (?, ?, ?), (?, ?, ?)
    `).bind(
      id, auth.user.id, now,
      id, other.id, now
    ),
  ]);

  return json({
    conversation: {
      id,
      otherUser: publicUser(other),
    },
  }, 201);
}

async function handleHistory(request, env) {
  const auth = await requireSession(request, env);

  if (auth.error) return auth.error;

  const url = new URL(request.url);
  const id = url.searchParams.get("conversationId");

  if (!isValidId(id)) {
    return json({ error: "Invalid conversation." }, 400);
  }

  if (!await isParticipant(env, id, auth.user.id)) {
    return json({ error: "Conversation not found." }, 404);
  }

  const room = env.CHAT_ROOM.getByName(id);

  const response = await room.fetch(
    "https://room.internal/history"
  );

  return new Response(response.body, {
    status: response.status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });
}

async function handleWebSocket(request, env) {
  const auth = await requireSession(request, env);

  if (auth.error) return auth.error;

  if (
    request.headers.get("Upgrade")?.toLowerCase() !== "websocket"
  ) {
    return json({
      error: "WebSocket upgrade required.",
    }, 426);
  }

  const url = new URL(request.url);
  const id = url.searchParams.get("conversationId");

  if (!isValidId(id)) {
    return json({ error: "Invalid conversation." }, 400);
  }

  if (!await isParticipant(env, id, auth.user.id)) {
    return json({ error: "Conversation not found." }, 404);
  }

  const room = env.CHAT_ROOM.getByName(id);
  const target = new URL("https://room.internal/websocket");

  // Use database-derived identity, never client-supplied identity.
  target.searchParams.set("uid", auth.user.id);
  target.searchParams.set("username", auth.user.username);
  target.searchParams.set(
    "displayName",
    auth.user.display_name
  );

  // Preserve the incoming WebSocket upgrade request.
  const forwarded = new Request(target, request);
  return room.fetch(forwarded);
}

async function api(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  if (path === "/api/health" && method === "GET") {
    return json({
      ok: true,
      service: "Orbit Chat",
    });
  }

  // Reject cross-origin state-changing requests.
  if (["POST", "PUT", "PATCH", "DELETE"].includes(method)) {
    const origin = request.headers.get("Origin");

    if (origin) {
      try {
        if (new URL(origin).origin !== url.origin) {
          return json({
            error: "Cross-origin request rejected.",
          }, 403);
        }
      } catch {
        return json({ error: "Invalid request origin." }, 403);
      }
    }
  }

  if (path === "/api/register" && method === "POST") {
    return handleRegister(request, env);
  }

  if (path === "/api/login" && method === "POST") {
    return handleLogin(request, env);
  }

  if (path === "/api/logout" && method === "POST") {
    return handleLogout(request, env);
  }

  if (path === "/api/me" && method === "GET") {
    const auth = await requireSession(request, env);

    if (auth.error) return auth.error;

    return json({
      user: publicUser(auth.user),
    });
  }

  if (path === "/api/users" && method === "GET") {
    return handleUserSearch(request, env);
  }

  if (path === "/api/conversations" && method === "GET") {
    return handleListConversations(request, env);
  }

  if (path === "/api/conversations" && method === "POST") {
    return handleCreateConversation(request, env);
  }

  if (path === "/api/history" && method === "GET") {
    return handleHistory(request, env);
  }

  if (path === "/api/ws" && method === "GET") {
    return handleWebSocket(request, env);
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
        SELECT
          id,
          user_id AS userId,
          username,
          display_name AS displayName,
          content,
          created_at AS createdAt
        FROM messages
        ORDER BY created_at DESC
        LIMIT 100
      `).toArray().reverse();

      return json({ messages: rows });
    }

    if (
      url.pathname !== "/websocket" ||
      request.headers.get("Upgrade")?.toLowerCase() !== "websocket"
    ) {
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

    server.serializeAttachment({
      uid,
      username,
      displayName,
    });

    return new Response(null, {
      status: 101,
      webSocket: client,
    });
  }

  async webSocketMessage(ws, raw) {
    const user = ws.deserializeAttachment();

    if (!user) return;

    let packet;

    try {
      if (typeof raw !== "string" || raw.length > 10000) {
        return;
      }

      packet = JSON.parse(raw);
    } catch {
      return;
    }

    if (packet.type !== "message") return;
    if (typeof packet.content !== "string") return;

    const content = packet.content.trim();

    if (!content || content.length > MESSAGE_MAX) {
      return;
    }

    const message = {
      id: crypto.randomUUID(),
      userId: user.uid,
      username: user.username,
      displayName: user.displayName,
      content,
      createdAt: Date.now(),
    };

    // Persist before broadcasting so history remains consistent.
    this.ctx.storage.sql.exec(`
      INSERT INTO messages (
        id,
        user_id,
        username,
        display_name,
        content,
        created_at
      )
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
        // A disconnected socket must not interrupt other clients.
      }
    }
  }

  webSocketClose(ws) {
    try {
      ws.close();
    } catch {
      // The connection may already be closed.
    }
  }

  webSocketError(ws) {
    try {
      ws.close(1011, "Connection error");
    } catch {
      // Ignore an already-closed connection.
    }
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
        response = new Response(
          "Orbit Chat assets are not configured.",
          { status: 503 }
        );
      }

      // Critical: preserve status 101 and its WebSocket object.
      return secureHeaders(response);
    
        } catch (error) {
      console.error("Orbit Chat request failed:", {
        path: new URL(request.url).pathname,
        method: request.method,
        error: error?.stack || String(error),
      });

      return secureHeaders(json({
        error: "Server error. Please try again.",
      }, 500));
    }
  },
};
