// server.js (ESM, because package.json has "type":"module")
import express from "express";
import path from "path";
import fs from "fs";
import http from "http";
import https from "https";
import crypto from "crypto";
import { fileURLToPath } from "url";
import dotenv from "dotenv";
import wispPkg from "wisp-server-node";

const wisp = wispPkg.default ?? wispPkg; // works whether wisp is CJS or ESM

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Match your original layout: serve from project root (parent of ./server)
const ROOT_DIR = path.join(process.cwd(), "..");
dotenv.config({ path: path.join(ROOT_DIR, ".env"), override: false });
dotenv.config({ path: path.join(__dirname, ".env"), override: true });
const LOGIN_HTML_PATH = path.join(__dirname, "login.html");
const USERS_PATH = path.join(__dirname, "users.json");
const OPEN_DIR = path.join(ROOT_DIR, "open");

const COOKIE_NAME = "fc_sso";
const COOKIE_MAX_AGE_MS = 1000 * 60 * 60 * 24 * 7; // 7 days
const COOKIE_SECURE = process.env.COOKIE_SECURE !== "false";
const COOKIE_BASE_OPTIONS = {
	httpOnly: true,
	sameSite: "strict",
	secure: COOKIE_SECURE,
	path: "/",
};

const COOKIE_SECRET = process.env.FC_SSO_SECRET || "change-me-fc_sso-secret";
if (!process.env.FC_SSO_SECRET) {
	console.warn(
		"[auth] Falling back to built-in FC_SSO secret. Set FC_SSO_SECRET to override.",
	);
}

const TURNSTILE_SECRET = process.env.TURNSTILE_SECRET || "";
const TURNSTILE_VERIFY_ENDPOINT =
	"https://challenges.cloudflare.com/turnstile/v0/siteverify";
if (!TURNSTILE_SECRET) {
	console.warn(
		"[auth] TURNSTILE_SECRET missing. Turnstile verification will reject all logins until it is set.",
	);
}

const AUTH_OPEN_PATHS = new Set(["/login", "/login.html", "/open"]);
const AUTH_OPEN_PREFIXES = ["/hwid/", "/open/"];

let usersCache = new Map();
let usersCacheMTime = 0;
let usersCacheMissingLogged = false;

function parseUsersJson(raw) {
	if (!raw || !raw.trim()) {
		return new Map();
	}
	let data;
	try {
		data = JSON.parse(raw);
	} catch (error) {
		throw new Error(`users.json is not valid JSON: ${error.message}`);
	}
	if (!data || !Array.isArray(data.users)) {
		throw new Error("users.json must contain {\"users\": [...]}.");
	}
	const map = new Map();
	for (const entry of data.users) {
		if (
			!entry ||
			typeof entry.username !== "string" ||
			typeof entry.salt !== "string" ||
			typeof entry.passwordHash !== "string"
		) {
			console.warn("[auth] Skipping malformed user entry in users.json");
			continue;
		}
		map.set(entry.username, {
			username: entry.username,
			salt: entry.salt,
			passwordHash: entry.passwordHash,
		});
	}
	return map;
}

function getUsersCache() {
	try {
		const stats = fs.statSync(USERS_PATH);
		if (stats.mtimeMs !== usersCacheMTime) {
			const raw = fs.readFileSync(USERS_PATH, "utf8");
			usersCache = parseUsersJson(raw);
			usersCacheMTime = stats.mtimeMs;
			usersCacheMissingLogged = false;
			console.log(
				`[auth] Loaded ${usersCache.size} account(s) from users.json`,
			);
		}
	} catch (error) {
		if (error.code === "ENOENT") {
			if (!usersCacheMissingLogged) {
				console.warn(
					`[auth] users.json not found at ${USERS_PATH}. Login will be disabled until it exists.`,
				);
				usersCacheMissingLogged = true;
			}
		} else if (error instanceof Error) {
			console.error(`[auth] Failed to load users.json: ${error.message}`);
		}
		usersCache = new Map();
		usersCacheMTime = 0;
	}
	return usersCache;
}

function parseCookies(header) {
	const cookies = {};
	if (!header) return cookies;
	for (const part of header.split(";")) {
		const [name, ...rest] = part.split("=");
		if (!name) continue;
		const trimmedName = name.trim();
		if (!trimmedName) continue;
		const rawValue = rest.join("=").trim();
		try {
			cookies[trimmedName] = decodeURIComponent(rawValue);
		} catch (error) {
			cookies[trimmedName] = rawValue;
		}
	}
	return cookies;
}

function getCookieValue(req, name) {
	if (!req._cookieCache) {
		req._cookieCache = parseCookies(req.headers.cookie || "");
	}
	return req._cookieCache[name];
}

function deriveSignature(username, passwordHash) {
	return crypto
		.createHmac("sha256", COOKIE_SECRET)
		.update(`${username}:${passwordHash}`)
		.digest("base64url");
}

function buildSessionToken(username, passwordHash) {
	const encodedUsername = Buffer.from(username, "utf8").toString("base64url");
	const signature = deriveSignature(username, passwordHash);
	return `${encodedUsername}.${signature}`;
}

function validateSession(token) {
	if (!token) return null;
	const parts = token.split(".");
	if (parts.length !== 2) return null;
	const [encodedUsername, providedSignature] = parts;
	let username;
	try {
		username = Buffer.from(encodedUsername, "base64url").toString("utf8");
	} catch (error) {
		return null;
	}
	const users = getUsersCache();
	const record = users.get(username);
	if (!record) return null;
	const expectedSignature = deriveSignature(username, record.passwordHash);
	let providedBuf;
	let expectedBuf;
	try {
		providedBuf = Buffer.from(providedSignature, "base64url");
		expectedBuf = Buffer.from(expectedSignature, "base64url");
	} catch (error) {
		return null;
	}
	if (providedBuf.length !== expectedBuf.length) return null;
	if (!crypto.timingSafeEqual(providedBuf, expectedBuf)) return null;
	return { username, record };
}

function hashPasswordCandidate(password, salt) {
	return crypto.scryptSync(password, salt, 64).toString("hex");
}

function safeRedirectTarget(value) {
	if (typeof value !== "string") return "/";
	if (!value.startsWith("/")) return "/";
	if (value.startsWith("//")) return "/";
	return value;
}

function setAuthCookie(res, username, passwordHash) {
	const token = buildSessionToken(username, passwordHash);
	res.cookie(COOKIE_NAME, token, {
		...COOKIE_BASE_OPTIONS,
		maxAge: COOKIE_MAX_AGE_MS,
	});
}

function clearAuthCookie(res) {
	res.clearCookie(COOKIE_NAME, COOKIE_BASE_OPTIONS);
}

function postFormEncoded(urlString, body) {
	const payload = typeof body === "string" ? body : String(body || "");
	const targetUrl = new URL(urlString);
	const options = {
		method: "POST",
		hostname: targetUrl.hostname,
		path: `${targetUrl.pathname}${targetUrl.search}`,
		headers: {
			"Content-Type": "application/x-www-form-urlencoded",
			"Content-Length": Buffer.byteLength(payload),
		},
	};
	return new Promise((resolve, reject) => {
		const request = https.request(options, (response) => {
			const chunks = [];
			response.on("data", (chunk) => chunks.push(chunk));
			response.on("end", () => {
				resolve({
					status: response.statusCode || 0,
					body: Buffer.concat(chunks).toString("utf8"),
				});
			});
		});
		request.on("error", (error) => reject(error));
		request.write(payload);
		request.end();
	});
}

function getClientIp(req) {
	const cfIp = req.headers["cf-connecting-ip"];
	if (typeof cfIp === "string" && cfIp.trim()) {
		return cfIp.trim();
	}
	const forwarded = req.headers["x-forwarded-for"];
	if (typeof forwarded === "string" && forwarded.trim()) {
		return forwarded.split(",")[0].trim();
	}
	return req.ip || req.socket?.remoteAddress || "";
}

async function verifyTurnstileResponse(token, remoteIp) {
	if (!TURNSTILE_SECRET) {
		console.error(
			"[auth] TURNSTILE_SECRET is not configured. Refusing to accept Turnstile responses.",
		);
		return false;
	}
	if (!token) {
		return false;
	}
	const form = new URLSearchParams();
	form.set("secret", TURNSTILE_SECRET);
	form.set("response", token);
	if (remoteIp) {
		form.set("remoteip", remoteIp);
	}
	const body = form.toString();
	try {
		let status = 0;
		let payloadText = "";
		if (typeof fetch === "function") {
			const response = await fetch(TURNSTILE_VERIFY_ENDPOINT, {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
				},
				body,
			});
			status = response.status;
			payloadText = await response.text();
		} else {
			const result = await postFormEncoded(TURNSTILE_VERIFY_ENDPOINT, body);
			status = result.status;
			payloadText = result.body;
		}
		if (status < 200 || status >= 300) {
			console.error(
				`[auth] Turnstile verification failed with status ${status}`,
			);
			return false;
		}
		let payload;
		try {
			payload = JSON.parse(payloadText);
		} catch (error) {
			console.error("[auth] Could not parse Turnstile response payload", error);
			return false;
		}
		if (!payload?.success) {
			const codes = Array.isArray(payload?.["error-codes"])
				? payload["error-codes"].join(", ")
				: "unknown";
			console.warn(`[auth] Turnstile rejected login attempt (${codes}).`);
			return false;
		}
		return true;
	} catch (error) {
		console.error(`[auth] Turnstile verification error: ${error}`);
		return false;
	}
}

// Debug a local app folder and mount it to /apps, patching config.json to force load it
const debugAppFolder = process.env.DEBUG_APP_FOLDER;
console.log(
	`For this run, app debugging will be ${debugAppFolder ? "enabled" : "disabled"}`,
);

const app = express();
app.set("trust proxy", true);
const httpPort = Number(process.env.PORT || 8000); // HTTP redirector
const httpsPort = Number(process.env.HTTPS_PORT || 443);

// --- Security / CORS headers ---
app.use((req, res, next) => {
	res.header("Cross-Origin-Embedder-Policy", "require-corp");
	res.header("Access-Control-Allow-Origin", "*");
	res.header("Cross-Origin-Opener-Policy", "same-origin");
	res.header("Cross-Origin-Resource-Policy", "same-site");
	res.header(
		"Strict-Transport-Security",
		"max-age=31536000; includeSubDomains; preload",
	);
	next();
});

app.use(express.urlencoded({ extended: false }));

app.use((req, _res, next) => {
	const token = getCookieValue(req, COOKIE_NAME);
	const session = validateSession(token);
	if (session) {
		req.user = { username: session.username };
	} else {
		req.user = null;
	}
	next();
});

app.get("/login", (req, res) => {
	if (req.user) {
		const target = safeRedirectTarget(req.query.next);
		return res.redirect(target);
	}
	res.setHeader("Cache-Control", "no-store");
	return res.sendFile(LOGIN_HTML_PATH);
});


app.post("/login", async (req, res) => {
	const body = req.body || {};
	const { username, password, next: nextRaw } = body;
	const nextTarget = safeRedirectTarget(nextRaw);
	const nextSuffix = nextTarget !== "/" ? `&next=${encodeURIComponent(nextTarget)}` : "";
	const captchaToken =
		typeof body["cf-turnstile-response"] === "string"
			? body["cf-turnstile-response"]
			: "";
	const remoteIp = getClientIp(req);
	const captchaOk = await verifyTurnstileResponse(captchaToken, remoteIp);
	if (!captchaOk) {
		return res.redirect(`/login?error=captcha${nextSuffix}`);
	}
	if (typeof username !== "string" || typeof password !== "string") {
		return res.redirect(`/login?error=invalid${nextSuffix}`);
	}
	const users = getUsersCache();
	const record = users.get(username);
	if (!record) {
		return res.redirect(`/login?error=invalid${nextSuffix}`);
	}
	let computedHash;
	try {
		computedHash = hashPasswordCandidate(password, record.salt);
	} catch (error) {
		console.error("[auth] Failed to hash incoming credentials", error);
		return res.redirect(`/login?error=invalid${nextSuffix}`);
	}
	let providedBuf;
	let storedBuf;
	try {
		providedBuf = Buffer.from(computedHash, "hex");
		storedBuf = Buffer.from(record.passwordHash, "hex");
	} catch (error) {
		console.error("[auth] Stored credentials for user are invalid", error);
		return res.redirect(`/login?error=invalid${nextSuffix}`);
	}
	if (providedBuf.length !== storedBuf.length) {
		return res.redirect(`/login?error=invalid${nextSuffix}`);
	}
	if (!crypto.timingSafeEqual(providedBuf, storedBuf)) {
		return res.redirect(`/login?error=invalid${nextSuffix}`);
	}
	setAuthCookie(res, username, record.passwordHash);
	return res.redirect(303, nextTarget);
});

app.post("/logout", (req, res) => {
	if (req.user) {
		clearAuthCookie(res);
	}
	res.redirect("/login");
});

app.use((req, res, next) => {
	if (req.user) return next();
	if (AUTH_OPEN_PATHS.has(req.path)) return next();
	if (AUTH_OPEN_PREFIXES.some((prefix) => req.path.startsWith(prefix))) {
		return next();
	}
	if (req.method === "GET" || req.method === "HEAD") {
		const target = safeRedirectTarget(req.originalUrl || "/");
		const suffix = target !== "/" ? `?next=${encodeURIComponent(target)}` : "";
		return res.redirect(302, `/login${suffix}`);
	}
	return res.status(401).json({ error: "Authentication required" });
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

	app.use(
		"/apps/anura-devserver-debug",
		express.static(path.resolve(debugAppFolder)),
	);
}

// --- Static mounts ---
if (fs.existsSync(OPEN_DIR)) {
	app.use("/open", express.static(OPEN_DIR));
} else {
	console.log(
		`[auth] Optional public directory not found at ${OPEN_DIR}. Create it to serve /open assets.`,
	);
}
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
http
	.createServer((req, res) => {
		const host = (req.headers.host || "").replace(/:\d+$/, "");
		res.writeHead(301, { Location: `https://${host}${req.url || "/"}` });
		res.end();
	})
	.listen(httpPort, () => {
		console.log(`↪️  HTTP redirector on :${httpPort} → HTTPS :${httpsPort}`);
	});
