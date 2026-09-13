import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json" }
  });
}

/* ============ PASSWORD HASHING (scrypt, built into Node — no extra dependency) ============ */
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${hash}`;
}
function verifyPassword(password, stored) {
  if (!stored || typeof stored !== "string" || !stored.includes(":")) return false;
  const [salt, hash] = stored.split(":");
  try {
    const hashBuffer = Buffer.from(hash, "hex");
    const testBuffer = crypto.scryptSync(password, salt, 64);
    if (hashBuffer.length !== testBuffer.length) return false;
    return crypto.timingSafeEqual(hashBuffer, testBuffer);
  } catch {
    return false;
  }
}

/* ============ SESSIONS ============ */
const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days
function generateToken() {
  return crypto.randomBytes(32).toString("hex");
}
async function createSession(sessionsStore, username) {
  const token = generateToken();
  await sessionsStore.setJSON(token, {
    username,
    createdAt: Date.now(),
    expiresAt: Date.now() + SESSION_TTL_MS
  });
  return token;
}
async function requireSession(body, sessionsStore) {
  const token = body && body.token;
  if (!token || typeof token !== "string") {
    return { error: json({ error: "Not signed in." }, 401) };
  }
  const session = await sessionsStore.get(token, { type: "json" });
  if (!session || session.expiresAt < Date.now()) {
    return { error: json({ error: "Your session has expired. Please sign in again." }, 401) };
  }
  return { username: session.username, token };
}

/* ============ LOGIN RATE LIMITING ============ */
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_WINDOW_MS = 15 * 60 * 1000; // 15 minutes
async function checkRateLimit(rateLimitStore, key) {
  const entry = await rateLimitStore.get(key, { type: "json" });
  if (!entry) return { blocked: false };
  const windowExpired = Date.now() - entry.firstAttemptAt > LOCKOUT_WINDOW_MS;
  if (windowExpired) return { blocked: false };
  if (entry.count >= MAX_LOGIN_ATTEMPTS) {
    const retryAfterMs = LOCKOUT_WINDOW_MS - (Date.now() - entry.firstAttemptAt);
    return { blocked: true, retryAfterMinutes: Math.ceil(retryAfterMs / 60000) };
  }
  return { blocked: false };
}
async function recordFailedLogin(rateLimitStore, key) {
  const entry = await rateLimitStore.get(key, { type: "json" });
  if (!entry || Date.now() - entry.firstAttemptAt > LOCKOUT_WINDOW_MS) {
    await rateLimitStore.setJSON(key, { count: 1, firstAttemptAt: Date.now() });
  } else {
    await rateLimitStore.setJSON(key, { count: entry.count + 1, firstAttemptAt: entry.firstAttemptAt });
  }
}
async function clearRateLimit(rateLimitStore, key) {
  await rateLimitStore.delete(key);
}

/* ============ SERVER-SIDE DATA VALIDATION ============ */
function isFiniteNumber(n) {
  return typeof n === "number" && Number.isFinite(n);
}
function isValidInstallment(inst) {
  if (typeof inst !== "object" || inst === null) return false;
  if (inst.amountDue !== undefined && (!isFiniteNumber(inst.amountDue) || inst.amountDue < 0 || inst.amountDue > 1e12)) return false;
  if (inst.amountReceived !== undefined && (!isFiniteNumber(inst.amountReceived) || inst.amountReceived < 0 || inst.amountReceived > 1e12)) return false;
  if (inst.dueDate !== undefined && inst.dueDate !== null && typeof inst.dueDate !== "string") return false;
  if (inst.receiptDate !== undefined && inst.receiptDate !== null && typeof inst.receiptDate !== "string") return false;
  return true;
}
function isValidAccounts(accounts) {
  if (!Array.isArray(accounts)) return false;
  if (accounts.length > 5000) return false;
  for (const acc of accounts) {
    if (typeof acc !== "object" || acc === null) return false;
    if (typeof acc.id !== "string" || acc.id.length > 100) return false;
    if (typeof acc.name !== "string" || acc.name.length > 300) return false;
    if (acc.total !== undefined && (!isFiniteNumber(acc.total) || acc.total < 0 || acc.total > 1e12)) return false;
    if (acc.downPayment !== undefined && (!isFiniteNumber(acc.downPayment) || acc.downPayment < 0 || acc.downPayment > 1e12)) return false;
    if (acc.installments !== undefined) {
      if (!Array.isArray(acc.installments) || acc.installments.length > 1000) return false;
      if (!acc.installments.every(isValidInstallment)) return false;
    }
  }
  return true;
}
function isValidPartners(partners) {
  if (!Array.isArray(partners)) return false;
  if (partners.length > 2000) return false;
  for (const p of partners) {
    if (typeof p !== "object" || p === null) return false;
    if (typeof p.id !== "string" || p.id.length > 100) return false;
    if (typeof p.name !== "string" || p.name.length > 300) return false;
    if (p.transactions !== undefined) {
      if (!Array.isArray(p.transactions) || p.transactions.length > 5000) return false;
      for (const t of p.transactions) {
        if (typeof t !== "object" || t === null) return false;
        if (t.amount !== undefined && (!isFiniteNumber(t.amount) || t.amount < 0 || t.amount > 1e12)) return false;
        if (t.type !== undefined && !["investment", "withdraw"].includes(t.type)) return false;
      }
    }
  }
  return true;
}

export default async (req) => {
  if (req.method !== "POST") {
    return json({ error: "Method not allowed" }, 405);
  }

  let body;
  try {
    body = await req.json();
  } catch (e) {
    return json({ error: "Invalid JSON" }, 400);
  }

  const { action } = body || {};
  const usersStore = getStore("il_users");
  const dataStore = getStore("il_userdata");
  const sessionsStore = getStore("il_sessions");
  const rateLimitStore = getStore("il_ratelimit");

  try {
    // ---- Create a new account ----
    if (action === "signup") {
      const { username, password, name } = body;
      if (!username || !password || !name) {
        return json({ error: "Please fill in all fields." }, 400);
      }
      if (typeof username !== "string" || username.length > 100 || typeof password !== "string" || password.length < 4) {
        return json({ error: "Please choose a username and a password of at least 4 characters." }, 400);
      }
      let users = (await usersStore.get("list", { type: "json" })) || [];
      if (users.find((u) => u.username.toLowerCase() === username.toLowerCase())) {
        return json({ error: "This username is already taken." }, 409);
      }
      users.push({ username, password: hashPassword(password), name });
      await usersStore.setJSON("list", users);
      await dataStore.setJSON(username.toLowerCase(), { accounts: [], partners: [] });
      const token = await createSession(sessionsStore, username);
      return json({ success: true, user: { username, name }, token });
    }

    // ---- Sign in with username + password ----
    if (action === "login") {
      const { username, password } = body;
      if (!username || !password) {
        return json({ error: "Please enter your username and password." }, 400);
      }
      const rlKey = String(username).toLowerCase();
      const rl = await checkRateLimit(rateLimitStore, rlKey);
      if (rl.blocked) {
        return json(
          { error: `Too many failed attempts. Please try again in ${rl.retryAfterMinutes} minute(s).` },
          429
        );
      }
      let users = (await usersStore.get("list", { type: "json" })) || [];
      const found = users.find((u) => u.username.toLowerCase() === username.toLowerCase());
      if (!found || !verifyPassword(password, found.password)) {
        await recordFailedLogin(rateLimitStore, rlKey);
        return json({ error: "Incorrect username or password." }, 401);
      }
      await clearRateLimit(rateLimitStore, rlKey);
      const token = await createSession(sessionsStore, found.username);
      return json({ success: true, user: { username: found.username, name: found.name }, token });
    }

    // ---- Resume a session on page load (validated by server-side token, not a client-supplied username) ----
    if (action === "session") {
      const auth = await requireSession(body, sessionsStore);
      if (auth.error) return auth.error;
      let users = (await usersStore.get("list", { type: "json" })) || [];
      const found = users.find((u) => u.username === auth.username);
      if (!found) return json({ error: "Session expired." }, 401);
      return json({ success: true, user: { username: found.username, name: found.name } });
    }

    // ---- Sign out (invalidate the session token server-side) ----
    if (action === "logout") {
      const token = body && body.token;
      if (token) await sessionsStore.delete(token);
      return json({ success: true });
    }

    // ---- Change password / username / name (requires a valid session) ----
    if (action === "updateUser") {
      const auth = await requireSession(body, sessionsStore);
      if (auth.error) return auth.error;
      const username = auth.username;
      const { updates = {} } = body;

      let users = (await usersStore.get("list", { type: "json" })) || [];
      const idx = users.findIndex((u) => u.username === username);
      if (idx === -1) return json({ error: "User not found." }, 404);

      if (updates.username && updates.username !== username) {
        if (typeof updates.username !== "string" || updates.username.length > 100) {
          return json({ error: "Invalid username." }, 400);
        }
        if (users.find((u) => u.username.toLowerCase() === updates.username.toLowerCase())) {
          return json({ error: "This username is already taken." }, 409);
        }
        const data = (await dataStore.get(username.toLowerCase(), { type: "json" })) || {
          accounts: [],
          partners: []
        };
        await dataStore.setJSON(updates.username.toLowerCase(), data);
        await dataStore.delete(username.toLowerCase());
        users[idx].username = updates.username;
        // Keep the same session token working, just pointed at the new username.
        await sessionsStore.setJSON(auth.token, {
          username: updates.username,
          createdAt: Date.now(),
          expiresAt: Date.now() + SESSION_TTL_MS
        });
      }
      if (updates.password) {
        if (typeof updates.password !== "string" || updates.password.length < 4) {
          return json({ error: "Password must be at least 4 characters." }, 400);
        }
        users[idx].password = hashPassword(updates.password);
      }
      if (updates.name) users[idx].name = updates.name;

      await usersStore.setJSON("list", users);
      return json({ success: true, user: { username: users[idx].username, name: users[idx].name } });
    }

    // ---- Fetch this user's accounts + business partners (only ever the authenticated user's own data) ----
    if (action === "getData") {
      const auth = await requireSession(body, sessionsStore);
      if (auth.error) return auth.error;
      const data = (await dataStore.get(auth.username.toLowerCase(), { type: "json" })) || {
        accounts: [],
        partners: []
      };
      return json({ success: true, accounts: data.accounts || [], partners: data.partners || [] });
    }

    // ---- Save this user's accounts + business partners (validated, own data only) ----
    if (action === "saveData") {
      const auth = await requireSession(body, sessionsStore);
      if (auth.error) return auth.error;
      const { accounts, partners } = body;

      if (accounts !== undefined && !isValidAccounts(accounts)) {
        return json({ error: "Account data failed validation and was not saved." }, 400);
      }
      if (partners !== undefined && !isValidPartners(partners)) {
        return json({ error: "Business partner data failed validation and was not saved." }, 400);
      }

      const key = auth.username.toLowerCase();
      const existing = (await dataStore.get(key, { type: "json" })) || {};
      const merged = {
        accounts: accounts !== undefined ? accounts : existing.accounts || [],
        partners: partners !== undefined ? partners : existing.partners || []
      };
      await dataStore.setJSON(key, merged);
      return json({ success: true });
    }

    return json({ error: "Unknown action." }, 400);
  } catch (e) {
    return json({ error: String((e && e.message) || e) }, 500);
  }
};

export const config = {
  path: "/api/ledger"
};
