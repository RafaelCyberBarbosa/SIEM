const API = {
  base: "",

  getToken() { return localStorage.getItem("siem_token"); },
  setToken(t) { localStorage.setItem("siem_token", t); },
  clearToken() { localStorage.removeItem("siem_token"); localStorage.removeItem("siem_user"); },

  getUser() {
    const raw = localStorage.getItem("siem_user");
    return raw ? JSON.parse(raw) : null;
  },
  setUser(u) { localStorage.setItem("siem_user", JSON.stringify(u)); },

  async request(path, options = {}) {
    const headers = options.headers || {};
    const token = this.getToken();
    if (token) headers["Authorization"] = "Bearer " + token;
    if (options.body && !(options.body instanceof URLSearchParams)) {
      headers["Content-Type"] = "application/json";
    }
    const resp = await fetch(this.base + path, { ...options, headers });
    if (resp.status === 401) {
      this.clearToken();
      window.location.reload();
      throw new Error("Unauthorized");
    }
    if (!resp.ok) {
      let detail = resp.statusText;
      try { const j = await resp.json(); detail = j.detail || JSON.stringify(j); } catch (e) {}
      throw new Error(detail);
    }
    if (resp.status === 204) return null;
    const text = await resp.text();
    return text ? JSON.parse(text) : null;
  },

  get(path) { return this.request(path, { method: "GET" }); },
  post(path, body) { return this.request(path, { method: "POST", body: JSON.stringify(body || {}) }); },
  patch(path, body) { return this.request(path, { method: "PATCH", body: JSON.stringify(body || {}) }); },
  del(path) { return this.request(path, { method: "DELETE" }); },

  async login(username, password) {
    const form = new URLSearchParams();
    form.set("username", username);
    form.set("password", password);
    const resp = await fetch(this.base + "/api/auth/login", { method: "POST", body: form });
    if (!resp.ok) {
      let detail = "Login failed";
      try { const j = await resp.json(); detail = j.detail || detail; } catch (e) {}
      throw new Error(detail);
    }
    const data = await resp.json();
    this.setToken(data.access_token);
    this.setUser({ username: data.username, role: data.role });
    return data;
  },
};

function toast(msg, type = "") {
  const el = document.createElement("div");
  el.className = "toast" + (type ? " " + type : "");
  el.textContent = msg;
  document.getElementById("toast-container").appendChild(el);
  setTimeout(() => el.remove(), 4500);
}

function fmtDate(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  return d.toLocaleString();
}

function severityBadge(sev) {
  return `<span class="badge sev-${sev}">${sev.toUpperCase()}</span>`;
}

function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  return String(str).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}
