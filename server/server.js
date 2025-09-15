// server.mjs — HTTPS + GTM injection for all HTML
import express from "express";
import path from "path";
import fs from "fs";
import https from "https";
import http from "http";
import wisp from "wisp-server-node";

const __dirname = path.join(process.cwd(), "..");
const DEBUG_APP_FOLDER = process.env.DEBUG_APP_FOLDER;
const SSL_PORT = process.env.SSL_PORT ? Number(process.env.SSL_PORT) : 443;
const REDIRECT_PORT = process.env.REDIRECT_PORT ? Number(process.env.REDIRECT_PORT) : 80;

// === TLS files (assumed names) ===
// If your cert/key filenames differ, change these two paths:
const TLS_CERT = "/home/f1xgod/fullchain.pem";
const TLS_KEY  = "/home/f1xgod/privkey.pem";

const gtmHead = `<!-- Google Tag Manager -->
<script>(function(w,d,s,l,i){w[l]=w[l]||[];w[l].push({'gtm.start':
new Date().getTime(),event:'gtm.js'});var f=d.getElementsByTagName(s)[0],
j=d.createElement(s),dl=l!='dataLayer'?'&l='+l:'';j.async=true;j.src=
'https://www.googletagmanager.com/gtm.js?id='+i+dl;f.parentNode.insertBefore(j,f);
})(window,document,'script','dataLayer','GTM-K6227GPN');</script>
<!-- End Google Tag Manager -->`;

const gtmNoScript = `<!-- Google Tag Manager (noscript) -->
<noscript><iframe src="https://www.googletagmanager.com/ns.html?id=GTM-K6227GPN"
height="0" width="0" style="display:none;visibility:hidden"></iframe></noscript>
<!-- End Google Tag Manager (noscript) -->`;

const app = express();

// Security-ish headers used previously
app.use((req, res, next) => {
  res.header("Cross-Origin-Embedder-Policy", "require-corp");
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Cross-Origin-Opener-Policy", "same-origin");
  res.header("Cross-Origin-Resource-Policy", "same-site");
  next();
});

// If debug app folder provided, patch /config.json and serve debug app
if (DEBUG_APP_FOLDER) {
  app.use((req, res, next) => {
    if (req.path === "/config.json") {
      const configPath = path.join(__dirname, "public", "config.json");
      fs.readFile(configPath, "utf8", (err, data) => {
        if (err) return next(err);
        try {
          const config = JSON.parse(data);
          config.apps = config.apps || [];
          config.apps.push("/apps/anura-devserver-debug");
          console.log("Serving patched config.json with debug app folder");
          return res.json(config);
        } catch (e) { return next(e); }
      });
    } else next();
  });

  app.use(
    "/apps/anura-devserver-debug",
    express.static(path.resolve(DEBUG_APP_FOLDER))
  );
}

// --- GTM injection middleware ---
// Buffer responses and inject GTM for HTML responses (safe for sendFile/streams)
app.use((req, res, next) => {
  // skip injection for non-GET/HEAD
  if (!["GET", "HEAD"].includes(req.method)) return next();

  const origWrite = res.write.bind(res);
  const origEnd = res.end.bind(res);
  let chunks = [];
  let isHtml = false;
  let headersSent = false;

  // Intercept header writes to detect Content-Type early if possible
  const origSetHeader = res.setHeader.bind(res);
  res.setHeader = (name, value) => {
    if (String(name).toLowerCase() === "content-type" && /html/i.test(String(value))) {
      isHtml = true;
    }
    return origSetHeader(name, value);
  };

  res.write = function (chunk, ...args) {
    // If headers already indicate non-html and were sent, passthrough
    if (headersSent && !isHtml) {
      return origWrite(chunk, ...args);
    }
    // buffer everything until end
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk)));
    return true;
  };

  res.end = function (chunk, ...args) {
    if (chunk) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk)));

    // Determine if HTML by headers or by content sniffing
    const ct = (res.getHeader("Content-Type") || "").toString();
    if (/html/i.test(ct)) isHtml = true;

    const bodyBuf = Buffer.concat(chunks || []);
    let body = bodyBuf.toString("utf8");

    // Heuristics: treat as HTML if contains <html> or <body> or </head> etc.
    if (!isHtml && (/<\/html>|<html|<body|<!doctype html/i.test(body))) {
      isHtml = true;
    }

    if (isHtml && body.length > 0 && !/GTM-K6227GPN/.test(body)) {
      // Inject GTM into <head> (as high as possible) and noscript right after <body>
      if (/<head[^>]*>/i.test(body)) {
        body = body.replace(/<head[^>]*>/i, match => match + "\n" + gtmHead);
      } else if (/<html[^>]*>/i.test(body)) {
        // no head tag — create one after <html>
        body = body.replace(/<html[^>]*>/i, match => match + "\n<head>\n" + gtmHead + "\n</head>");
      } else {
        // fallback: prepend
        body = gtmHead + "\n" + body;
      }

      if (/<body[^>]*>/i.test(body)) {
        body = body.replace(/<body[^>]*>/i, match => match + "\n" + gtmNoScript);
      } else {
        // fallback: put noscript at top
        body = gtmNoScript + "\n" + body;
      }
    }

    // update Content-Length if set
    if (res.getHeader("Content-Length")) {
      res.setHeader("Content-Length", Buffer.byteLength(body));
    }

    // send modified body
    return origEnd(body, ...args);
  };

  // allow other middlewares to run
  next();
});

// Serve static folders (keeps your original behavior)
app.use(express.static(path.join(__dirname, "public")));
app.use(express.static(path.join(__dirname, "build")));
app.use("/bin", express.static(path.join(__dirname, "bin")));
app.use("/apps", express.static(path.join(__dirname, "apps")));
app.use(express.static(path.join(__dirname, "aboutproxy", "static")));

// If you still want a plain http server for local dev (non-ssl), keep optional port behavior:
// but production: HTTPS server on 443 will be used.

function startServers() {
  // read certs (will throw if not found)
  let sslOptions;
  try {
    sslOptions = {
      key: fs.readFileSync(TLS_KEY),
      cert: fs.readFileSync(TLS_CERT),
    };
  } catch (e) {
    console.error("ERROR reading TLS certs. Expected at:", TLS_KEY, TLS_CERT);
    console.error(e);
    process.exit(1);
  }

  const httpsServer = https.createServer(sslOptions, app);

  httpsServer.listen(SSL_PORT, () => {
    console.log(`✅ HTTPS listening on port ${SSL_PORT}`);
  });

  // redirect HTTP -> HTTPS
  const redirectApp = (req, res) => {
    const host = req.headers.host ? req.headers.host.split(":")[0] : "localhost";
    const dest = `https://${host}${req.url}`;
    res.writeHead(301, { Location: dest });
    res.end();
  };
  const httpServer = http.createServer(redirectApp);
  httpServer.listen(REDIRECT_PORT, () => {
    console.log(`→ HTTP redirector listening on port ${REDIRECT_PORT} -> https`);
  });

  // preserve your wisp upgrade routing on the HTTPS server (websockets)
  httpsServer.on("upgrade", (request, socket, head) => {
    wisp.routeRequest(request, socket, head);
  });

  // keep the old interface for logs if needed
  httpsServer.on("listening", () => {
    console.log("Server ready. GTM injection active. Certs loaded from:", TLS_CERT, TLS_KEY);
  });

  httpsServer.on("error", (err) => {
    console.error("HTTPS server error:", err);
  });
}

startServers();
