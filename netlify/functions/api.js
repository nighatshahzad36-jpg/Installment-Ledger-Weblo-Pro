import { getStore } from "@netlify/blobs";

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json" }
  });
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

  try {
    // ---- Create a new account ----
    if (action === "signup") {
      const { username, password, name } = body;
      if (!username || !password || !name) {
        return json({ error: "Please fill in all fields." }, 400);
      }

      let users = (await usersStore.get("list", { type: "json" })) || [];
      if (users.find(u => u.username.toLowerCase() === username.toLowerCase())) {
        return json({ error: "This username is already taken." }, 409);
      }

      users.push({ username, password, name });
      await usersStore.setJSON("list", users);
      await dataStore.setJSON(username.toLowerCase(), { accounts: [], partners: [] });
      return json({ success: true, user: { username, name } });
    }

    // ---- Sign in with username + password ----
    if (action === "login") {
      const { username, password } = body;
      let users = (await usersStore.get("list", { type: "json" })) || [];
      const found = users.find(
        u => u.username.toLowerCase() === (username || "").toLowerCase() && u.password === password
      );

      if (!found) return json({ error: "Incorrect username or password." }, 401);
      return json({ success: true, user: { username: found.username, name: found.name } });
    }

    // ---- Resume a session on page load (no password re-check, mirrors the old localStorage session) ----
    if (action === "session") {
      const { username } = body;
      let users = (await usersStore.get("list", { type: "json" })) || [];
      const found = users.find(u => u.username === username);
      if (!found) return json({ error: "Session expired." }, 401);
      return json({ success: true, user: { username: found.username, name: found.name } });
    }

    // ---- Change password / username / name ----
    if (action === "updateUser") {
      const { username, updates = {} } = body;
      let users = (await usersStore.get("list", { type: "json" })) || [];
      const idx = users.findIndex(u => u.username === username);
      if (idx === -1) return json({ error: "User not found." }, 404);

      if (updates.username && updates.username !== username) {
        if (users.find(u => u.username.toLowerCase() === updates.username.toLowerCase())) {
          return json({ error: "This username is already taken." }, 409);
        }

        // Move this user's data blob over to the new username key.
        const data = (await dataStore.get(username.toLowerCase(), { type: "json" })) || {
          accounts: [],
          partners: []
        };

        await dataStore.setJSON(updates.username.toLowerCase(), data);
        await dataStore.delete(username.toLowerCase());
        users[idx].username = updates.username;
      }

      if (updates.password) users[idx].password = updates.password;
      if (updates.name) users[idx].name = updates.name;

      await usersStore.setJSON("list", users);
      return json({ success: true, user: { username: users[idx].username, name: users[idx].name } });
    }

    // ---- Fetch this user's accounts + business partners ----
    if (action === "getData") {
      const { username } = body;
      const data = (await dataStore.get(username.toLowerCase(), { type: "json" })) || {
        accounts: [],
        partners: []
      };

      return json({ success: true, accounts: data.accounts || [], partners: data.partners || [] });
    }

    // ---- Save this user's accounts + business partners ----
    if (action === "saveData") {
      const { username, accounts, partners } = body;
      const existing = (await dataStore.get(username.toLowerCase(), { type: "json" })) || {};

      const merged = {
        accounts: accounts !== undefined ? accounts : existing.accounts || [],
        partners: partners !== undefined ? partners : existing.partners || []
      };

      await dataStore.setJSON(username.toLowerCase(), merged);
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
