// Watch Ensemble — serveur de synchronisation
// Node 18+ requis (fetch natif). Lancer avec : node server.js

const http = require("http");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const dns = require("node:dns").promises;
const net = require("node:net");
const express = require("express");
const multer = require("multer");
const { WebSocketServer, WebSocket } = require("ws");

const PORT = process.env.PORT || 3000;
const UPLOAD_DIR = path.join(__dirname, "uploads");
const MAX_UPLOAD_MB = Number(process.env.MAX_UPLOAD_MB || 1024); // 1 Go par défaut

fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const app = express();
app.disable("x-powered-by");
// Render (et la plupart des hébergeurs) placent l'app derrière un proxy :
// nécessaire pour que req.ip reflète la vraie IP cliente (rate-limiting).
app.set("trust proxy", true);

// ---------------------------------------------------------------------------
// Anti-SSRF : refuse toute cible qui résout vers une adresse interne.
// (Protège /api/extract : sans ça, un visiteur pourrait faire lire au serveur
//  http://169.254.169.254/… — métadonnées cloud — ou des services internes.)
// Limite connue : petite fenêtre TOCTOU entre la résolution DNS et la requête ;
// suffisant contre les abus courants, pas contre un attaquant très déterminé.
// ---------------------------------------------------------------------------
function isPrivateIPv4(ip) {
  const p = ip.split(".").map(Number);
  if (p.length !== 4 || p.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return true;
  const [a, b] = p;
  if (a === 0 || a === 10 || a === 127) return true;
  if (a === 169 && b === 254) return true;          // link-local
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16/12
  if (a === 192 && b === 168) return true;          // 192.168/16
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT 100.64/10
  if (a >= 224) return true;                         // multicast / réservé
  return false;
}
function isPrivateIP(ip) {
  if (net.isIPv4(ip)) return isPrivateIPv4(ip);
  if (net.isIPv6(ip)) {
    const low = ip.toLowerCase();
    if (low === "::1" || low === "::") return true;
    if (low.startsWith("fe80")) return true;              // link-local
    if (low.startsWith("fc") || low.startsWith("fd")) return true; // ULA fc00::/7
    const m = low.match(/::ffff:(\d+\.\d+\.\d+\.\d+)$/);  // IPv4-mappé
    if (m) return isPrivateIPv4(m[1]);
    return false;
  }
  return true; // format inconnu -> refus
}
async function assertPublicHost(urlStr) {
  let u;
  try { u = new URL(urlStr); } catch { throw new Error("URL invalide."); }
  if (!/^https?:$/.test(u.protocol)) throw new Error("Seul http/https est autorisé.");
  const host = u.hostname;
  if (net.isIP(host)) {
    if (isPrivateIP(host)) throw new Error("Adresse réseau interne refusée.");
    return u;
  }
  if (/^(localhost|.*\.local)$/i.test(host)) throw new Error("Nom d'hôte local refusé.");
  let addrs;
  try { addrs = await dns.lookup(host, { all: true }); }
  catch { throw new Error("Nom d'hôte introuvable."); }
  if (!addrs.length) throw new Error("Nom d'hôte introuvable.");
  for (const a of addrs) {
    if (isPrivateIP(a.address)) throw new Error("Ce nom pointe vers une adresse interne (refusé).");
  }
  return u;
}

// ---------------------------------------------------------------------------
// Rate-limiting mémoire (léger, sans dépendance) : borne les endpoints
// publics coûteux (upload, extraction) pour éviter les abus.
// ---------------------------------------------------------------------------
const rlHits = new Map();
function rateLimit(max, windowMs) {
  return (req, res, next) => {
    const ip = req.ip || (req.socket && req.socket.remoteAddress) || "?";
    const now = Date.now();
    let rec = rlHits.get(ip);
    if (!rec || now > rec.reset) { rec = { count: 0, reset: now + windowMs }; rlHits.set(ip, rec); }
    rec.count++;
    if (rec.count > max) {
      return res.status(429).json({ error: "Trop de requêtes, réessaie dans un instant." });
    }
    next();
  };
}
setInterval(() => {
  const now = Date.now();
  for (const [ip, rec] of rlHits) if (now > rec.reset) rlHits.delete(ip);
}, 5 * 60 * 1000).unref();

// ---------------------------------------------------------------------------
// Fichiers statiques
// ---------------------------------------------------------------------------
app.use(express.static(path.join(__dirname, "public")));

// Les vidéos téléversées (express.static gère les requêtes Range,
// indispensables pour pouvoir avancer/reculer dans la vidéo).
app.use("/media", express.static(UPLOAD_DIR, { fallthrough: false }));

// La page d'une salle est la même page HTML, le JS lit le code dans l'URL.
app.get("/room/:id", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ---------------------------------------------------------------------------
// Upload de vidéos locales
// ---------------------------------------------------------------------------
const ALLOWED_EXT = new Set([".mp4", ".m4v", ".mov", ".webm", ".mp3", ".m4a"]);

const storage = multer.diskStorage({
  destination: UPLOAD_DIR,
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname || "").toLowerCase();
    cb(null, crypto.randomBytes(8).toString("hex") + ext);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: MAX_UPLOAD_MB * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname || "").toLowerCase();
    cb(null, ALLOWED_EXT.has(ext));
  },
});

app.post("/api/upload", rateLimit(20, 60_000), (req, res) => {
  upload.single("video")(req, res, (err) => {
    if (err) {
      const msg =
        err.code === "LIMIT_FILE_SIZE"
          ? `Fichier trop volumineux (max ${MAX_UPLOAD_MB} Mo).`
          : "Échec du téléversement.";
      return res.status(400).json({ error: msg });
    }
    if (!req.file) {
      return res
        .status(400)
        .json({ error: "Format non pris en charge (MP4, MOV, M4V, WebM)." });
    }
    res.json({
      url: "/media/" + req.file.filename,
      title: req.file.originalname || req.file.filename,
    });
  });
});

// ---------------------------------------------------------------------------
// Extraction de vidéos depuis une page web
// (on cherche les sources directes MP4/WebM/HLS/DASH dans le HTML de la page)
// ---------------------------------------------------------------------------
app.get("/api/extract", rateLimit(30, 60_000), async (req, res) => {
  const pageURL = String(req.query.url || "");
  let base;
  try {
    base = await assertPublicHost(pageURL); // valide protocole + refuse cibles internes
  } catch (e) {
    return res.status(400).json({ error: e.message || "URL de page invalide." });
  }

  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 10_000);
    const resp = await fetch(base.href, {
      signal: ctrl.signal,
      redirect: "follow",
      headers: {
        "user-agent":
          "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile Safari/604.1",
        accept: "text/html,application/xhtml+xml",
      },
    });
    clearTimeout(timer);

    const html = (await resp.text()).slice(0, 3_000_000);
    const found = new Map(); // url -> label

    // 1) URLs directes vers des fichiers/flux vidéo dans le HTML
    const directRe =
      /https?:\/\/[^\s"'<>\\]+?\.(?:mp4|m4v|webm|mov|m3u8|mpd)(?:\?[^\s"'<>\\]*)?/gi;
    for (const m of html.matchAll(directRe)) {
      addCandidate(found, m[0], base);
    }

    // 2) Attributs src des balises <video> / <source>
    const srcRe = /<(?:video|source)\b[^>]*?\bsrc\s*=\s*["']([^"']+)["']/gi;
    for (const m of html.matchAll(srcRe)) {
      addCandidate(found, m[1], base);
    }

    const videos = [...found.keys()].slice(0, 10).map((u) => ({
      url: u,
      kind: /\.m3u8(\?|$)/i.test(u) ? "Flux HLS"
          : /\.mpd(\?|$)/i.test(u) ? "Flux DASH"
          : "Fichier vidéo",
    }));

    res.json({ videos });
  } catch {
    res.status(502).json({
      error:
        "Impossible de lire cette page. Certains sites bloquent ce type d'accès.",
    });
  }
});

function addCandidate(map, raw, base) {
  try {
    const u = new URL(raw, base).href;
    if (u.startsWith("blob:")) return; // illisible hors de la page d'origine
    if (!/\.(mp4|m4v|webm|mov|m3u8|mpd)(\?|$)/i.test(u)) return;
    if (!map.has(u)) map.set(u, true);
  } catch {
    /* ignore */
  }
}

// ---------------------------------------------------------------------------
// Synchronisation temps réel (WebSocket)
// ---------------------------------------------------------------------------
const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: "/ws" });

const MAX_PARTICIPANTS = 2; // « séance privée » : la salle admet 2 personnes

const rooms = new Map();

// ---------------------------------------------------------------------------
// Persistance « best-effort » des salles sur disque : au réveil du serveur
// (Render Free se met en veille après ~15 min d'inactivité), l'état des salles
// et la liste des épisodes prêts survivent, au lieu de repartir de zéro.
// On ne sérialise QUE {state, playlist} — jamais les sockets clients.
// ---------------------------------------------------------------------------
const STATE_FILE = path.join(__dirname, "rooms.json");
let persistTimer = null;
function schedulePersist() {
  if (persistTimer) return;
  persistTimer = setTimeout(() => {
    persistTimer = null;
    const out = {};
    for (const [id, room] of rooms) {
      out[id] = { state: room.state, playlist: room.playlist };
    }
    fs.writeFile(STATE_FILE, JSON.stringify(out), () => {});
  }, 1500);
}
function loadRooms() {
  let raw;
  try { raw = JSON.parse(fs.readFileSync(STATE_FILE, "utf8")); } catch { return; }
  const now = Date.now();
  for (const id of Object.keys(raw || {})) {
    const r = raw[id];
    if (!r || !r.state) continue;
    // On ne restaure que les salles utilisées dans les dernières 24 h.
    if (now - (r.state.updatedAt || 0) > 24 * 3600 * 1000) continue;
    rooms.set(id, { state: r.state, playlist: r.playlist || [], clients: new Set() });
  }
}
loadRooms();

// Balayage périodique : retire les salles vides et inactives (> 2 h) pour ne
// pas garder en mémoire des salles restaurées que plus personne ne rejoint.
setInterval(() => {
  const now = Date.now();
  let changed = false;
  for (const [id, room] of rooms) {
    if (room.clients.size === 0 && now - (room.state.updatedAt || 0) > 2 * 3600 * 1000) {
      rooms.delete(id); changed = true;
    }
  }
  if (changed) schedulePersist();
}, 30 * 60 * 1000).unref();

function firstClient(room) {
  return room.clients.size ? room.clients.values().next().value : null;
}

function getRoom(id) {
  if (!rooms.has(id)) {
    rooms.set(id, {
      state: { url: null, title: null, playing: false, time: 0, updatedAt: Date.now() },
      playlist: [],   // épisodes prêts : [{ url, title }]
      clients: new Set(),
    });
  }
  return rooms.get(id);
}

function currentState(room) {
  const s = room.state;
  const time = s.playing ? s.time + (Date.now() - s.updatedAt) / 1000 : s.time;
  return { url: s.url, title: s.title, playing: s.playing, time, playlist: room.playlist };
}

function sendTo(ws, msg) {
  if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(msg));
}

function broadcast(roomId, msg, except = null) {
  const room = rooms.get(roomId);
  if (!room) return;
  for (const client of room.clients) {
    if (client !== except) sendTo(client, msg);
  }
}

function sanitizeRoomId(raw) {
  return String(raw || "").replace(/[^A-Za-z0-9]/g, "").slice(0, 16);
}

// Applique une action à l'état de la salle. Renvoie true si l'action est
// valide (et doit être rediffusée), false sinon. Partagé entre le chemin
// « participant » (WebSocket d'un membre) et le chemin « push » (téléchargeur).
function applyActionToRoom(room, a) {
  const s = room.state;
  switch (a.kind) {
    case "load":
      s.url = String(a.url || "").slice(0, 2048);
      s.title = String(a.title || "").slice(0, 200);
      s.playing = false;
      s.time = 0;
      s.updatedAt = Date.now();
      return true;
    case "play":
      s.playing = true;
      s.time = Number(a.time) || 0;
      s.updatedAt = Date.now();
      return true;
    case "pause":
      s.playing = false;
      s.time = Number(a.time) || 0;
      s.updatedAt = Date.now();
      return true;
    case "seek":
      s.time = Number(a.time) || 0;
      s.playing = !!a.playing;
      s.updatedAt = Date.now();
      return true;
    case "add": {
      const url = String(a.url || "").slice(0, 2048);
      if (!url) return false;
      if (room.playlist.length < 50 && !room.playlist.some((e) => e.url === url)) {
        room.playlist.push({ url, title: String(a.title || "").slice(0, 200) });
      }
      return true;
    }
    case "remove":
      room.playlist = room.playlist.filter((e) => e.url !== String(a.url || ""));
      return true;
    default:
      return false;
  }
}

wss.on("connection", (ws) => {
  ws.roomId = null;
  ws.isAlive = true;
  ws.on("pong", () => (ws.isAlive = true));

  ws.on("message", (data) => {
    let msg;
    try {
      msg = JSON.parse(data);
    } catch {
      return;
    }

    // --- Synchronisation d'horloge : le serveur est l'horloge de référence.
    //     Le client mesure ainsi le décalage entre son horloge et celle du
    //     serveur, pour compenser la latence réseau sur play/seek/resume. ---
    if (msg.type === "ping") {
      sendTo(ws, { type: "pong", t0: msg.t0, ts: Date.now() });
      return;
    }

    // --- Push « one-shot » du téléchargeur : applique une action et la
    //     rediffuse SANS occuper une des 2 places de la salle. -----------
    if (msg.type === "push" && msg.action) {
      const id = sanitizeRoomId(msg.room);
      if (!id) return;
      const room = getRoom(id);
      if (applyActionToRoom(room, msg.action)) {
        msg.action.at = Date.now();
        broadcast(id, { type: "action", action: msg.action });
        schedulePersist();
      }
      return;
    }

    if (msg.type === "join") {
      const id = sanitizeRoomId(msg.room);
      if (!id) return;
      const room = getRoom(id);
      // Salle pleine : on refuse poliment (sans compter un éventuel socket
      // déjà présent, ex. rechargement de page dont la fermeture n'est pas
      // encore arrivée).
      if (!room.clients.has(ws) && room.clients.size >= MAX_PARTICIPANTS) {
        sendTo(ws, { type: "full", max: MAX_PARTICIPANTS });
        return;
      }
      ws.roomId = id;
      room.clients.add(ws);
      // Le premier client d'une salle est le « meneur » : c'est lui qui pilote
      // l'enchaînement automatique des épisodes (évite le double-chargement).
      sendTo(ws, {
        type: "state",
        state: currentState(room),
        leader: firstClient(room) === ws,
        at: Date.now(),
      });
      broadcast(id, { type: "peers", count: room.clients.size });
      return;
    }

    if (!ws.roomId) return;
    const room = getRoom(ws.roomId);

    if (msg.type === "requestState") {
      sendTo(ws, { type: "state", state: currentState(room), at: Date.now() });
      return;
    }

    // Coordination du buffering : « je charge, attends-moi » / « c'est reparti ».
    // Simple relais entre les 2 membres (n'altère pas l'état de la salle).
    if (msg.type === "stall" || msg.type === "resume") {
      broadcast(ws.roomId, { type: msg.type, time: Number(msg.time) || 0, at: Date.now() }, ws);
      return;
    }

    // Signalisation WebRTC (appel vidéo) : relais brut entre les membres.
    if (msg.type === "rtc" && msg.payload) {
      broadcast(ws.roomId, { type: "rtc", payload: msg.payload }, ws);
      return;
    }

    if (msg.type === "action" && msg.action) {
      if (applyActionToRoom(room, msg.action)) {
        msg.action.at = Date.now(); // horodatage serveur pour la compensation
        broadcast(ws.roomId, { type: "action", action: msg.action }, ws);
        schedulePersist();
      }
    }
  });

  ws.on("close", () => {
    if (!ws.roomId || !rooms.has(ws.roomId)) return;
    const roomId = ws.roomId;
    const room = rooms.get(roomId);
    room.clients.delete(ws);
    broadcast(roomId, { type: "peers", count: room.clients.size });
    // Promeut le client restant en « meneur » (si le meneur vient de partir).
    const nf = firstClient(room);
    if (nf) sendTo(nf, { type: "role", leader: true });
    // Nettoyage des salles vides après 10 minutes
    if (room.clients.size === 0) {
      setTimeout(() => {
        const r = rooms.get(roomId);
        if (r && r.clients.size === 0) rooms.delete(roomId);
      }, 10 * 60 * 1000);
    }
  });
});

// Ping périodique pour fermer les connexions mortes
setInterval(() => {
  for (const ws of wss.clients) {
    if (!ws.isAlive) {
      ws.terminate();
      continue;
    }
    ws.isAlive = false;
    ws.ping();
  }
}, 30_000);

server.listen(PORT, () => {
  console.log(`Watch Ensemble en écoute sur http://localhost:${PORT}`);
});
