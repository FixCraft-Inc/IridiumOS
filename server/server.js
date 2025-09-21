// server.js (ESM, because package.json has "type":"module")
import express from "express";
import path from "path";
import fs from "fs";
import http from "http";
import https from "https";
import wispPkg from "wisp-server-node";

const wisp = wispPkg.default ?? wispPkg; // works whether wisp is CJS or ESM

// Match your original layout: serve from project root (parent of ./server)
const ROOT_DIR = path.join(process.cwd(), "..");

// Debug a local app folder and mount it to /apps, patching config.json to force load it
const debugAppFolder = process.env.DEBUG_APP_FOLDER;
console.log(`For this run, app debugging will be ${debugAppFolder ? "enabled" : "disabled"}`);

const app = express();
const httpPort = Number(process.env.PORT || 8000);   // HTTP redirector
const httpsPort = Number(process.env.HTTPS_PORT || 443);

// --- Security / CORS headers ---
app.use((req, res, next) => {
  res.header("Cross-Origin-Embedder-Policy", "require-corp");
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Cross-Origin-Opener-Policy", "same-origin");
  res.header("Cross-Origin-Resource-Policy", "same-site");
  res.header("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload");
  next();
});

// --- Debug app passthrough ---
if (debugAppFolder) {
  app.use((req, res, next) => {
    if (req.path === "/config.json") {
      const configPath = path.join(ROOT_DIR, "public", "config.json");
      fs.readFile(configPath, "utf8", (err, data) => {
        if (err) return next(err);
        const config = JSON.parse(data || "{}");
        if (!config.apps) config.apps = [];
        if (!config.apps.includes("/apps/anura-devserver-debug")) {
          config.apps.push("/apps/anura-devserver-debug");
        }
        console.log("Serving patched config.json with debug app folder");
        res.json(config);
      });
    } else {
      next();
    }
  });

  app.use("/apps/anura-devserver-debug", express.static(path.resolve(debugAppFolder)));
}

// --- Static mounts ---
app.use(express.static(path.join(ROOT_DIR, "public")));
app.use(express.static(path.join(ROOT_DIR, "build")));
app.use("/bin", express.static(path.join(ROOT_DIR, "bin")));
app.use("/apps", express.static(path.join(ROOT_DIR, "apps")));
app.use(express.static(path.join(ROOT_DIR, "aboutproxy", "static")));

// --- TLS (Cloudflare origin key/cert) ---
const TLS_KEY = "/home/f1xgod/cloudf.key";
const TLS_CERT = "/home/f1xgod/cloudf.pem";

const httpsOptions = {
  key: fs.readFileSync(TLS_KEY),
  cert: fs.readFileSync(TLS_CERT),
  // If your cert isn't a full chain, add:
  // ca: fs.readFileSync("/path/to/chain.pem"),
};

// --- HTTPS primary ---
const httpsServer = https.createServer(httpsOptions, app);
httpsServer.listen(httpsPort, () => {
  console.log(`✅ HTTPS listening on :${httpsPort}`);
});

// WISP over WSS
httpsServer.on("upgrade", (request, socket, head) => {
  wisp.routeRequest(request, socket, head);
});

// --- Optional HTTP → HTTPS redirector ---
http.createServer((req, res) => {
  const host = (req.headers.host || "").replace(/:\d+$/, "");
  res.writeHead(301, { Location: `https://${host}${req.url || "/"}` });
  res.end();
}).listen(httpPort, () => {
  console.log(`↪️  HTTP redirector on :${httpPort} → HTTPS :${httpsPort}`);
});
