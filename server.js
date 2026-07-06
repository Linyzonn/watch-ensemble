// Watch Ensemble — serveur de synchronisation
// Node 18+ requis (fetch natif). Lancer avec : node server.js

const http = require("http");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const express = require("express");
const multer = require("multer");
const { WebSocketServer, WebSocket } = require("ws");

const PORT = process.env.PORT || 3000;
const UPLOAD_DIR = path.join(__dirname, "uploads");
const MAX_UPLOAD_MB = Number(process.env.MAX_UPLOAD_MB || 1024); // 1 Go par défaut

fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const app = express();
app.disable("x-powered-by");

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

app.post("/api/upload", (req, res) => {
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
// (équivalent de la "reconnaissance des vidéos" : on cherche les sources
// directes MP4/WebM/HLS dans le HTML de la page)
// ---------------------------------------------------------------------------
app.get("/api/extract", async (req, res) => {
  const pageURL = String(req.query.url || "");
  let base;
  try {
    base = new URL(pageURL);
    if (!/^https?:$/.test(base.protocol)) throw new Error("bad protocol");
  } catch {
    return res.status(400).json({ error: "URL de page invalide." });
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
      /https?:\/\/[^\s"'<>\\]+?\.(?:mp4|m4v|webm|mov|m3u8)(?:\?[^\s"'<>\\]*)?/gi;
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
      kind: /\.m3u8(\?|$)/i.test(u) ? "Flux HLS" : "Fichier vidéo",
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
    if (!/\.(mp4|m4v|webm|mov|m3u8)(\?|$)/i.test(u)) return;
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

/**
 * rooms : id -> {
 *   state: { url, title, playing, time, updatedAt },
 *   clients: Set<WebSocket>
 * }
 * Le serveur est la source de vérité : quand quelqu'un arrive en cours de
 * lecture, on lui envoie la position calculée à l'instant T.
 */
const rooms = new Map();

function getRoom(id) {
  if (!rooms.has(id)) {
    rooms.set(id, {
      state: { url: null, title: null, playing: false, time: 0, updatedAt: Date.now() },
      clients: new Set(),
    });
  }
  return rooms.get(id);
}

function currentState(room) {
  const s = room.state;
  const time = s.playing ? s.time + (Date.now() - s.updatedAt) / 1000 : s.time;
  return { url: s.url, title: s.title, playing: s.playing, time };
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

    if (msg.type === "join") {
      const id = String(msg.room || "")
        .replace(/[^A-Za-z0-9]/g, "")
        .slice(0, 16);
      if (!id) return;
      ws.roomId = id;
      const room = getRoom(id);
      room.clients.add(ws);
      sendTo(ws, { type: "state", state: currentState(room) });
      broadcast(id, { type: "peers", count: room.clients.size });
      return;
    }

    if (!ws.roomId) return;
    const room = getRoom(ws.roomId);

    if (msg.type === "requestState") {
      sendTo(ws, { type: "state", state: currentState(room) });
      return;
    }

    if (msg.type === "action" && msg.action) {
      const a = msg.action;
      const s = room.state;
      switch (a.kind) {
        case "load":
          s.url = String(a.url || "").slice(0, 2048);
          s.title = String(a.title || "").slice(0, 200);
          s.playing = false;
          s.time = 0;
          s.updatedAt = Date.now();
          break;
        case "play":
          s.playing = true;
          s.time = Number(a.time) || 0;
          s.updatedAt = Date.now();
          break;
        case "pause":
          s.playing = false;
          s.time = Number(a.time) || 0;
          s.updatedAt = Date.now();
          break;
        case "seek":
          s.time = Number(a.time) || 0;
          s.playing = !!a.playing;
          s.updatedAt = Date.now();
          break;
        default:
          return;
      }
      broadcast(ws.roomId, { type: "action", action: a }, ws);
    }
  });

  ws.on("close", () => {
    if (!ws.roomId || !rooms.has(ws.roomId)) return;
    const roomId = ws.roomId;
    const room = rooms.get(roomId);
    room.clients.delete(ws);
    broadcast(roomId, { type: "peers", count: room.clients.size });
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
