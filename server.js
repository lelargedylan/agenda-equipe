/**
 * Serveur "Agenda d'équipe"
 * -------------------------
 * Agenda partagé + mémos privés + tchat + amis/messages privés + fichiers.
 * Stockage : simple fichier data.json sur le disque du serveur (persistant
 * tant que l'hébergeur ne réinitialise pas le disque - voir README pour
 * les options avec disque persistant gratuit).
 */

const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

const PORT = process.env.PORT || 3000;
const DATA_FILE = path.join(__dirname, "data.json");

/* ---------------- Stockage fichier (avec file d'attente d'écriture) --------------- */
function emptyState() {
  return {
    config: null, // { accessCode, hostName, hostPasswordHash, salt }
    agenda: [], // { id, day (YYYY-MM-DD), title, desc, by, createdAt }
    chat: [], // { id, author, text, ts }
    memos: {}, // { [name]: { [day]: text } }
    memoSecrets: {}, // { [name]: hashedSecret } - verrouille les mémos/calendrier par personne
    friends: [], // { id, a, b, status, requestedBy }
    dms: {}, // { [pairKey]: [ {id, author, text, ts} ] }
    files: [], // { id, name, kind, content, by, ts }
  };
}

let state = null;
function loadState() {
  if (fs.existsSync(DATA_FILE)) {
    try {
      state = JSON.parse(fs.readFileSync(DATA_FILE, "utf-8"));
    } catch {
      state = emptyState();
    }
  } else {
    state = emptyState();
  }
}
let saving = false;
let pendingSave = false;
function saveState() {
  if (saving) {
    pendingSave = true;
    return;
  }
  saving = true;
  fs.writeFile(DATA_FILE, JSON.stringify(state, null, 2), (err) => {
    saving = false;
    if (err) console.error("Erreur d'écriture:", err);
    if (pendingSave) {
      pendingSave = false;
      saveState();
    }
  });
}
loadState();

/* ---------------- Utilitaires ---------------- */
function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 32).toString("hex");
}
function hashToken(token) {
  return crypto.createHash("sha256").update(String(token)).digest("hex");
}
function uid() {
  return crypto.randomBytes(6).toString("hex");
}
function pairKey(a, b) {
  return [a, b].map((s) => s.trim().toLowerCase()).sort().join("::");
}
function badRequest(res, msg) {
  return res.status(400).json({ error: msg });
}

/* ---------------- Config (hôte / accès) ---------------- */
app.get("/api/config", (req, res) => {
  res.json({ initialized: !!state.config });
});

app.post("/api/config/create", (req, res) => {
  if (state.config) return badRequest(res, "L'agenda est déjà initialisé.");
  const { hostName, accessCode, hostPassword } = req.body || {};
  if (!hostName?.trim() || !accessCode?.trim() || !hostPassword?.trim()) {
    return badRequest(res, "Champs manquants.");
  }
  const salt = crypto.randomBytes(8).toString("hex");
  state.config = {
    hostName: hostName.trim(),
    accessCode: accessCode.trim(),
    salt,
    hostPasswordHash: hashPassword(hostPassword.trim(), salt),
  };
  saveState();
  res.json({ ok: true });
});

app.post("/api/config/join", (req, res) => {
  if (!state.config) return badRequest(res, "Agenda non initialisé.");
  const { accessCode } = req.body || {};
  if (accessCode?.trim() !== state.config.accessCode) {
    return res.status(401).json({ error: "Code d'accès incorrect." });
  }
  res.json({ ok: true });
});

app.post("/api/config/host-login", (req, res) => {
  if (!state.config) return badRequest(res, "Agenda non initialisé.");
  const { hostPassword } = req.body || {};
  const hash = hashPassword(hostPassword?.trim() || "", state.config.salt);
  if (hash !== state.config.hostPasswordHash) {
    return res.status(401).json({ error: "Mot de passe hôte incorrect." });
  }
  res.json({ ok: true });
});
app.post("/api/memos/reset", (req, res) => {
  if (!state.config) return badRequest(res, "Agenda non initialisé.");
  const { name, hostPassword } = req.body || {};
  if (!name?.trim() || !hostPassword) return badRequest(res, "Champs manquants.");
  const hash = hashPassword(hostPassword.trim(), state.config.salt);
  if (hash !== state.config.hostPasswordHash) {
    return res.status(401).json({ error: "Mot de passe hôte incorrect." });
  }
  if (!state.memoSecrets) state.memoSecrets = {};
  delete state.memoSecrets[name.trim()];
  saveState();
  res.json({ ok: true });
});
/* ---------------- Agenda ---------------- */
app.get("/api/agenda", (req, res) => res.json(state.agenda));

app.post("/api/agenda", (req, res) => {
  const { day, title, desc, by } = req.body || {};
  if (!day || !title?.trim() || !by?.trim()) return badRequest(res, "Champs manquants.");
  const event = { id: uid(), day, title: title.trim(), desc: (desc || "").trim(), by: by.trim(), createdAt: Date.now() };
  state.agenda.push(event);
  saveState();
  res.json(event);
});

app.delete("/api/agenda/:id", (req, res) => {
  state.agenda = state.agenda.filter((e) => e.id !== req.params.id);
  saveState();
  res.json({ ok: true });
});

/* ---------------- Tchat public ---------------- */
app.get("/api/chat", (req, res) => {
  const since = Number(req.query.since || 0);
  res.json(state.chat.filter((m) => m.ts > since));
});

app.post("/api/chat", (req, res) => {
  const { author, text } = req.body || {};
  if (!author?.trim() || !text?.trim()) return badRequest(res, "Champs manquants.");
  const msg = { id: uid(), author: author.trim(), text: text.trim(), ts: Date.now() };
  state.chat.push(msg);
  if (state.chat.length > 500) state.chat = state.chat.slice(-500);
  saveState();
  res.json(msg);
});

/* ---------------- Mémos privés ---------------- */
app.get("/api/memos", (req, res) => {
  const name = (req.query.name || "").trim();
  const secret = (req.query.secret || "").trim();
  if (!name || !secret) return badRequest(res, "Nom ou clé manquant.");
  if (!state.memoSecrets) state.memoSecrets = {};
  const h = hashToken(secret);
  if (!state.memoSecrets[name]) {
    state.memoSecrets[name] = h;
    saveState();
  } else if (state.memoSecrets[name] !== h) {
    return res.status(403).json({ error: "Accès refusé : ce calendrier appartient à quelqu'un d'autre." });
  }
  res.json(state.memos[name] || {});
});

app.post("/api/memos", (req, res) => {
  const { name, day, text, secret } = req.body || {};
  if (!name?.trim() || !day || !secret) return badRequest(res, "Champs manquants.");
  if (!state.memoSecrets) state.memoSecrets = {};
  const trimmedName = name.trim();
  const h = hashToken(secret);
  if (!state.memoSecrets[trimmedName]) {
    state.memoSecrets[trimmedName] = h;
  } else if (state.memoSecrets[trimmedName] !== h) {
    return res.status(403).json({ error: "Accès refusé : ce calendrier appartient à quelqu'un d'autre." });
  }
  if (!state.memos[trimmedName]) state.memos[trimmedName] = {};
  state.memos[trimmedName][day] = text || "";
  saveState();
  res.json({ ok: true });
});

/* ---------------- Amis ---------------- */
app.get("/api/friends", (req, res) => res.json(state.friends));

app.post("/api/friends/request", (req, res) => {
  const { from, to } = req.body || {};
  if (!from?.trim() || !to?.trim()) return badRequest(res, "Champs manquants.");
  if (from.trim().toLowerCase() === to.trim().toLowerCase()) return badRequest(res, "Impossible.");
  const exists = state.friends.find((f) => pairKey(f.a, f.b) === pairKey(from, to));
  if (exists) return badRequest(res, "Déjà en relation.");
  const req_ = { id: uid(), a: from.trim(), b: to.trim(), status: "pending", requestedBy: from.trim() };
  state.friends.push(req_);
  saveState();
  res.json(req_);
});

app.post("/api/friends/:id/respond", (req, res) => {
  const { accept } = req.body || {};
  if (accept) {
    state.friends = state.friends.map((f) => (f.id === req.params.id ? { ...f, status: "accepted" } : f));
  } else {
    state.friends = state.friends.filter((f) => f.id !== req.params.id);
  }
  saveState();
  res.json({ ok: true });
});

/* ---------------- Messages privés ---------------- */
app.get("/api/dm/:a/:b", (req, res) => {
  const key = pairKey(req.params.a, req.params.b);
  const since = Number(req.query.since || 0);
  res.json((state.dms[key] || []).filter((m) => m.ts > since));
});

app.post("/api/dm/:a/:b", (req, res) => {
  const key = pairKey(req.params.a, req.params.b);
  const { author, text } = req.body || {};
  if (!author?.trim() || !text?.trim()) return badRequest(res, "Champs manquants.");
  if (!state.dms[key]) state.dms[key] = [];
  const msg = { id: uid(), author: author.trim(), text: text.trim(), ts: Date.now() };
  state.dms[key].push(msg);
  if (state.dms[key].length > 500) state.dms[key] = state.dms[key].slice(-500);
  saveState();
  res.json(msg);
});

/* ---------------- Fichiers / documents partagés ---------------- */
app.get("/api/files", (req, res) => res.json(state.files));

app.post("/api/files", (req, res) => {
  const { name, kind, content, by } = req.body || {};
  if (!name?.trim() || !content?.trim() || !by?.trim()) return badRequest(res, "Champs manquants.");
  const file = { id: uid(), name: name.trim(), kind: kind === "link" ? "link" : "text", content: content.trim(), by: by.trim(), ts: Date.now() };
  state.files.push(file);
  saveState();
  res.json(file);
});

app.delete("/api/files/:id", (req, res) => {
  state.files = state.files.filter((f) => f.id !== req.params.id);
  saveState();
  res.json({ ok: true });
});

/* ---------------- Page d'accueil (fallback SPA) ---------------- */
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, () => {
  console.log(`Serveur lancé sur http://localhost:${PORT}`);
});
