// server.js (ESM, because package.json has "type":"module")
import express from "express";
import path from "path";
import fs from "fs";
import http from "http";
import https from "https";
import crypto from "crypto";
import { spawnSync } from "child_process";
import { fileURLToPath } from "url";
import dotenv from "dotenv";
import readline from "readline";
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
const VPN_ARCHIVE_PATH = path.join(__dirname, "vpn_db.tar.xz");
const PROTON_ARCHIVE_PATH = path.join(__dirname, "protonext.tar.xz");
const RUNTIME_DIR = path.join(__dirname, ".irRUNTIME");
const VPN_DB_PATH = path.join(RUNTIME_DIR, "vpn_db.bin");
const PROTON_DB_PATH = path.join(RUNTIME_DIR, "protonext.json");
const RUNTIME_LOCK_PATH = path.join(RUNTIME_DIR, ".lock");
const VPN_BLOCKED_HTML_PATH = path.join(__dirname, "vpn-blocked.html");
const DIRECT_IP_BLOCKED_HTML_PATH = path.join(__dirname, "direct-ip-blocked.html");
const DIRECT_IP_BLOCK_FALLBACK_HTML = `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Access blocked</title><style>body{margin:0;font-family:system-ui;background:#05060a;color:#f5f5f5;display:flex;align-items:center;justify-content:center;min-height:100vh}main{max-width:460px;padding:32px;border-radius:18px;background:#0f111c;box-shadow:0 20px 55px rgba(0,0,0,.45);text-align:center;border:1px solid rgba(255,255,255,.1)}h1{margin:0 0 12px;font-size:1.9rem}p{margin:0 0 14px;line-height:1.5;color:#cbd5f5}</style></head><body><main><h1>Firewall-chan stopped you!</h1><p>{{MESSAGE}}</p><p>Please use the official hostname or contact your admin.</p></main></body></html>`;
const DIRECT_IP_BLOCK_MESSAGE_PLACEHOLDER = /\{\{MESSAGE\}\}/g;
const DIRECT_IP_DEFAULT_MESSAGE =
	"Our cute firewall only trusts official hostnames.";
const OPEN_DIR = path.join(ROOT_DIR, "open");
const PUBLIC_CONFIG_PATH = path.join(ROOT_DIR, "public", "config.json");
const DEFAULT_CONFIG_PATH = path.join(ROOT_DIR, "config.default.json");
const TWEB_DIR = path.join(__dirname, "tweb");
const TWEB_PACKAGE_JSON_PATH = path.join(TWEB_DIR, "package.json");
const TWEB_NODE_MODULES_DIR = path.join(TWEB_DIR, "node_modules");
const VPN_DETECTION_ENABLED =
	((process.env.VPN_DETECTION_ENABLED ?? "true").toLowerCase() !== "false");
let LOGIN_HTML_TEMPLATE = "";
try {
	LOGIN_HTML_TEMPLATE = fs.readFileSync(LOGIN_HTML_PATH, "utf8");
} catch (error) {
	console.error(
		`[boot] Failed to read login template at ${LOGIN_HTML_PATH}: ${
			error instanceof Error ? error.message : error
		}`,
	);
	process.exit(1);
}
const ENV_FILE_CANDIDATES = [
	path.join(ROOT_DIR, ".env"),
	path.join(__dirname, ".env"),
];

function pickEnvFileForWrites() {
	for (const candidate of ENV_FILE_CANDIDATES) {
		if (fs.existsSync(candidate)) {
			return candidate;
		}
	}
	return ENV_FILE_CANDIDATES[ENV_FILE_CANDIDATES.length - 1];
}

function upsertEnvValue(key, value) {
	const targetPath = pickEnvFileForWrites();
	let original = "";
	try {
		original = fs.existsSync(targetPath)
			? fs.readFileSync(targetPath, "utf8")
			: "";
	} catch {
		original = "";
	}
	const lines = original.split(/\r?\n/);
	const matcher = new RegExp(`^\\s*${key}\\s*=`);
	let replaced = false;
	const nextLines = lines
		.filter((line, idx, arr) => !(line === "" && idx === arr.length - 1))
		.map((line) => {
			if (matcher.test(line)) {
				replaced = true;
				return `${key}=${value}`;
			}
			return line;
		});
	if (!replaced) {
		nextLines.push(`${key}=${value}`);
	}
	const payload = `${nextLines.join("\n")}\n`;
	fs.writeFileSync(targetPath, payload, "utf8");
	return targetPath;
}

function parseBoolean(value, defaultValue = false) {
	if (value === undefined || value === null) return defaultValue;
	const normalized = String(value).trim().toLowerCase();
	if (!normalized) return defaultValue;
	return !["0", "false", "off", "no"].includes(normalized);
}

const launchedByRunServer = process.env.IR_SERVER_LAUNCHER === "run-server";
const allowDirectServerLaunch = parseBoolean(
	process.env.IR_ALLOW_DIRECT_SERVER ?? "false",
	false,
);
if (!launchedByRunServer && !allowDirectServerLaunch) {
	console.error(
		"[boot] Direct 'node server.js' execution is disabled. Please run './run-server.sh' or 'make server'.",
	);
	process.exit(1);
}

const consoleModePreference = (
	process.env.IR_SERVER_CONSOLE_MODE || "interactive"
).toLowerCase();
const interactiveConsoleRequested = consoleModePreference !== "noninteractive";
const stdinIsTTY = Boolean(process.stdin.isTTY);
if (interactiveConsoleRequested && !stdinIsTTY) {
	console.warn(
		"[console] Interactive mode requested but stdin is not a TTY; falling back to non-interactive mode.",
	);
}
const consoleMode =
	interactiveConsoleRequested && stdinIsTTY ? "interactive" : "noninteractive";
const interactiveConsoleEnabled = consoleMode === "interactive";
console.log(
	`[console] Mode: ${
		interactiveConsoleEnabled
			? "interactive (type 'stop' to shut down)"
			: "non-interactive (signals only)"
	}`,
);

let consoleInterface = null;
let consoleClosing = false;
let consoleShimInstalled = false;
const consoleShimMethods = ["log", "warn", "error"];

function refreshConsolePrompt() {
	if (
		!interactiveConsoleEnabled ||
		!consoleInterface ||
		consoleClosing ||
		shutdownController?.isShuttingDown?.()
	) {
		return;
	}
	try {
		consoleInterface.prompt(true);
	} catch {
		// ignore prompt refresh errors
	}
}

function installConsolePromptShim() {
	if (consoleShimInstalled || !interactiveConsoleEnabled) {
		return;
	}
	consoleShimInstalled = true;
	for (const method of consoleShimMethods) {
		const original = console[method];
		if (typeof original !== "function") continue;
		console[method] = (...args) => {
			original(...args);
			refreshConsolePrompt();
		};
	}
}

function generateCookieSecret() {
	return crypto.randomBytes(32).toString("base64url");
}

function isSecureCookieSecret(value) {
	if (typeof value !== "string") return false;
	const trimmed = value.trim();
	if (trimmed.length < 43) return false; // ~32 bytes when base64url
	if (/^very_random32bit$/i.test(trimmed)) return false;
	if (/^change-me-fc_sso-secret$/i.test(trimmed)) return false;
	return true;
}

function ensureCookieSecret() {
	let current = process.env.FC_SSO_SECRET;
	if (isSecureCookieSecret(current)) {
		return current.trim();
	}
	const freshSecret = generateCookieSecret();
	const targetPath = upsertEnvValue("FC_SSO_SECRET", freshSecret);
	process.env.FC_SSO_SECRET = freshSecret;
	console.warn(
		`[auth] FC_SSO_SECRET was missing or weak. Generated a new 256-bit secret and stored it in ${targetPath}`,
	);
	return freshSecret;
}

const USE_CF = parseBoolean(process.env.USE_CF, true);
const ENABLE_LOCAL_DDOS_GUARD = parseBoolean(
	process.env.ENABLE_LOCAL_DDOS_GUARD ?? "true",
	true,
);
const SERVER_SECRETS_DIR = path.join(__dirname, "secrets");
const DEFAULT_CF_TLS_CERT = path.join(SERVER_SECRETS_DIR, "cloudf.pem");
const DEFAULT_CF_TLS_KEY = path.join(SERVER_SECRETS_DIR, "cloudf.key");
const DEFAULT_ORIGIN_TLS_CERT = path.join(SERVER_SECRETS_DIR, "fullchain.pem");
const DEFAULT_ORIGIN_TLS_KEY = path.join(SERVER_SECRETS_DIR, "privkey.pem");
const TLS_CERT_PATH =
	process.env.TLS_CERT ||
	(USE_CF ? DEFAULT_CF_TLS_CERT : DEFAULT_ORIGIN_TLS_CERT);
const TLS_KEY_PATH =
	process.env.TLS_KEY || (USE_CF ? DEFAULT_CF_TLS_KEY : DEFAULT_ORIGIN_TLS_KEY);
const DROP_PRIVS_USER = process.env.DROP_PRIVS_USER || "nobody";
const DROP_PRIVS_GROUP = process.env.DROP_PRIVS_GROUP || "nogroup";
const SHOULD_DROP_ROOT =
	typeof process.getuid === "function" && process.getuid() === 0;
const HTTPS_PORT = Number(process.env.HTTPS_PORT || (USE_CF ? 3433 : 443));
const TWEB_HTTPS_PORT = Number(
	process.env.TWEB_HTTPS_PORT || (USE_CF ? 3434 : HTTPS_PORT),
);
const HTTP_PORT = Number(process.env.HTTP_PORT || 80);
const ENABLE_HTTP_REDIRECT = USE_CF
	? false
	: parseBoolean(process.env.ENABLE_HTTP_REDIRECT ?? "true", true);
const USE_SEPARATE_TWEB_PORT = TWEB_HTTPS_PORT !== HTTPS_PORT;
const RATE_LIMIT_WINDOW_MS = Number(process.env.RATE_LIMIT_WINDOW_MS || 15000);
const RATE_LIMIT_MAX_REQUESTS = Number(
	process.env.RATE_LIMIT_MAX_REQUESTS || 300,
);
const CLOUDFLARE_IPV4_CIDRS = [
	"173.245.48.0/20",
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"141.101.64.0/18",
	"108.162.192.0/18",
	"190.93.240.0/20",
	"188.114.96.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	"162.158.0.0/15",
	"104.16.0.0/13",
	"104.24.0.0/14",
	"172.64.0.0/13",
	"131.0.72.0/22",
];
const CLOUDFLARE_IPV6_CIDRS = [
	"2400:cb00::/32",
	"2606:4700::/32",
	"2803:f800::/32",
	"2405:b500::/32",
	"2405:8100::/32",
	"2a06:98c0::/29",
	"2c0f:f248::/32",
];
const CLOUDFLARE_IPV4_RANGES = CLOUDFLARE_IPV4_CIDRS.map(parseIpv4Cidr).filter(
	Boolean,
);
const CLOUDFLARE_IPV6_RANGES = CLOUDFLARE_IPV6_CIDRS.map(parseIpv6Cidr).filter(
	Boolean,
);
const DIRECT_IP_HOST_PATTERN =
	/^(\d{1,3}\.){3}\d{1,3}$|^\[?([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\]?$/;


const COOKIE_NAME = "fc_sso";
const COOKIE_MAX_AGE_MS = 1000 * 60 * 60 * 24 * 7; // 7 days
const COOKIE_SECURE = process.env.COOKIE_SECURE !== "false";
const COOKIE_DOMAIN =
	typeof process.env.COOKIE_DOMAIN === "string"
		? process.env.COOKIE_DOMAIN.trim() || null
		: null;
const COOKIE_BASE_OPTIONS = {
	httpOnly: true,
	sameSite: "strict",
	secure: COOKIE_SECURE,
	path: "/",
	...(COOKIE_DOMAIN ? { domain: COOKIE_DOMAIN } : {}),
};

if (COOKIE_DOMAIN) {
	console.log(`[auth] SSO cookie will be shared across subdomains via ${COOKIE_DOMAIN}`);
} else {
	console.log("[auth] COOKIE_DOMAIN not set. SSO cookie will be bound to the exact host.");
}

const COOKIE_SECRET = ensureCookieSecret();

const TURNSTILE_SECRET = (process.env.TURNSTILE_SECRET || "").trim();
const TURNSTILE_SITE_KEY = (process.env.TURNSTILE_SITE_KEY || "").trim();
const GTM_CONTAINER_ID = (process.env.GTM_CONTAINER_ID || "").trim();
const TURNSTILE_VERIFY_ENDPOINT =
	"https://challenges.cloudflare.com/turnstile/v0/siteverify";
if (!TURNSTILE_SECRET) {
	console.warn(
		"[auth] TURNSTILE_SECRET missing. Turnstile verification will reject all logins until it is set.",
	);
}
if (!TURNSTILE_SITE_KEY) {
	console.warn(
		"[auth] TURNSTILE_SITE_KEY missing. Turnstile widget cannot render until it is set.",
	);
}
if (USE_CF && (!TURNSTILE_SECRET || !TURNSTILE_SITE_KEY)) {
	console.error(
		"[boot] USE_CF=true requires both TURNSTILE_SECRET and TURNSTILE_SITE_KEY. Refusing to start.",
	);
	process.exit(1);
}

const AUTH_OPEN_PATHS = new Set([
	"/login",
	"/login.html",
	"/open",
	"/manifest.json",
	"/permission-guard.js",
]);
const AUTH_OPEN_PREFIXES = ["/hwid/", "/open/"];
const TWEB_AUTH_OPEN_PATHS = new Set(["/login", "/login.html"]);
const TWEB_AUTH_OPEN_PREFIXES = [];

let usersCache = new Map();
let usersCacheMTime = 0;
let usersCacheMissingLogged = false;

// VPN IP blocking cache
const createEmptyVpnData = () => ({
	providers: ["unknown"],
	ipv4Exact: {
		values: new Uint32Array(0),
		providers: new Uint16Array(0),
	},
	ipv4Ranges: {
		start: new Uint32Array(0),
		end: new Uint32Array(0),
		providers: new Uint16Array(0),
	},
	ipv6Exact: {
		values: [],
		providers: new Uint16Array(0),
	},
	ipv6Ranges: {
		start: [],
		end: [],
		providers: new Uint16Array(0),
	},
	stats: {
		ipv4Exact: 0,
		ipv4Ranges: 0,
		ipv6Exact: 0,
		ipv6Ranges: 0,
	},
});

let vpnData = createEmptyVpnData();
let vpnCacheMTime = 0;
let vpnCacheMissingLogged = false;
let runtimeLockFd = null;
let runtimeGuardInterval = null;
const protonAddon = {
	enabled: false,
	byIp: new Map(),
	generatedAt: null,
};
let vpnBlockedTemplate = null;
let directIpBlockedTemplate = null;

const formatInteger = (value) => {
	try {
		return Number(value || 0).toLocaleString("en-US");
	} catch {
		return String(value);
	}
};

function escapeHtml(value) {
	return String(value ?? "")
		.replace(/&/g, "&amp;")
		.replace(/</g, "&lt;")
		.replace(/>/g, "&gt;")
		.replace(/"/g, "&quot;")
		.replace(/'/g, "&#39;");
}

function loadDirectIpBlockedTemplate() {
	if (directIpBlockedTemplate) {
		return directIpBlockedTemplate;
	}
	try {
		const template = fs.readFileSync(DIRECT_IP_BLOCKED_HTML_PATH, "utf8");
		if (template && template.includes("{{MESSAGE}}")) {
			directIpBlockedTemplate = template;
		} else {
			console.warn(
				`[security] Direct IP block page is missing the {{MESSAGE}} placeholder. Using fallback template.`,
			);
			directIpBlockedTemplate = DIRECT_IP_BLOCK_FALLBACK_HTML;
		}
	} catch (error) {
		console.warn(
			`[security] Could not read ${DIRECT_IP_BLOCKED_HTML_PATH}: ${
				error instanceof Error ? error.message : error
			}. Using fallback template.`,
		);
		directIpBlockedTemplate = DIRECT_IP_BLOCK_FALLBACK_HTML;
	}
	return directIpBlockedTemplate;
}

function sendHtmlResponse(res, statusCode, html) {
	const payload = typeof html === "string" ? html : "";
	if (res.headersSent) {
		return;
	}
	if (typeof res.status === "function" && typeof res.send === "function") {
		res.status(statusCode);
		if (typeof res.type === "function") {
			res.type("text/html; charset=utf-8");
		} else if (typeof res.set === "function") {
			res.set("Content-Type", "text/html; charset=utf-8");
		} else if (typeof res.setHeader === "function") {
			res.setHeader("Content-Type", "text/html; charset=utf-8");
		}
		res.send(payload);
		return;
	}
	res.statusCode = statusCode;
	if (typeof res.setHeader === "function") {
		res.setHeader("Content-Type", "text/html; charset=utf-8");
	}
	res.end(payload);
}

function renderDirectIpBlockedPage(
	res,
	message = DIRECT_IP_DEFAULT_MESSAGE,
	statusCode = 403,
) {
	const template = loadDirectIpBlockedTemplate();
	const html = template.replace(
		DIRECT_IP_BLOCK_MESSAGE_PLACEHOLDER,
		escapeHtml(message || DIRECT_IP_DEFAULT_MESSAGE),
	);
	sendHtmlResponse(res, statusCode, html);
}

function ensureRuntimeDirectory(mode = 0o755) {
	fs.mkdirSync(RUNTIME_DIR, { recursive: true, mode });
}

function extractArchive(archivePath, { clean = false } = {}) {
	console.log(`[security] 🗜️ Extracting ${path.basename(archivePath)} → ${RUNTIME_DIR}`);
	if (clean) {
		try {
			fs.rmSync(RUNTIME_DIR, { recursive: true, force: true });
		} catch {
			// ignore
		}
	}
	ensureRuntimeDirectory();
	const result = spawnSync("tar", ["-xJf", archivePath, "-C", RUNTIME_DIR], {
		stdio: "inherit",
	});
	if (result.error) {
		throw result.error;
	}
	if (typeof result.status === "number" && result.status !== 0) {
		throw new Error(`tar exited with code ${result.status}`);
	}
}

function ensureArchive(archivePath, expectedFile, { clean = false } = {}) {
	if (!fs.existsSync(archivePath)) {
		return false;
	}
	let needsExtract = clean;
	try {
		const archiveStats = fs.statSync(archivePath);
		const targetStats = fs.statSync(expectedFile);
		if (targetStats.size <= 0 || targetStats.mtimeMs < archiveStats.mtimeMs) {
			needsExtract = true;
		}
	} catch {
		needsExtract = true;
	}
	if (needsExtract) {
		extractArchive(archivePath, { clean });
	}
	return true;
}

function lockRuntimeDir() {
	if (runtimeLockFd !== null) return;
	ensureRuntimeDirectory();
	runtimeLockFd = fs.openSync(RUNTIME_LOCK_PATH, "w");
	fs.writeSync(runtimeLockFd, `pid=${process.pid}\nstarted=${new Date().toISOString()}\n`);
	fs.fsyncSync(runtimeLockFd);
}

function unlockRuntimeDir() {
	if (runtimeLockFd === null) return;
	try {
		fs.closeSync(runtimeLockFd);
	} catch {
		// ignore
	}
	runtimeLockFd = null;
	try {
		fs.rmSync(RUNTIME_LOCK_PATH, { force: true });
	} catch {
		// ignore
	}
}

function freezeRuntimeDir() {
	try {
		fs.chmodSync(RUNTIME_DIR, 0o555);
	} catch {
		// ignore
	}
}

function thawRuntimeDir() {
	try {
		fs.chmodSync(RUNTIME_DIR, 0o755);
	} catch {
		// ignore
	}
}

function startRuntimeGuard() {
	if (runtimeGuardInterval) return;
	runtimeGuardInterval = setInterval(() => {
		const dirMissing = !fs.existsSync(RUNTIME_DIR);
		const binMissing = !fs.existsSync(VPN_DB_PATH);
		const protonRequired = fs.existsSync(PROTON_ARCHIVE_PATH);
		const protonMissing = protonRequired && !fs.existsSync(PROTON_DB_PATH);
		if (!dirMissing && !binMissing && !protonMissing) {
			return;
		}
	console.warn("[security] ⚠️ VPN runtime directory missing; attempting to restore.");
	try {
		thawRuntimeDir();
		unlockRuntimeDir();
		const mainOk = ensureArchive(VPN_ARCHIVE_PATH, VPN_DB_PATH, { clean: true });
		if (!mainOk) {
			console.error("[security] ❌ VPN archive missing; cannot restore runtime directory.");
			return;
		}
		if (fs.existsSync(PROTON_ARCHIVE_PATH)) {
			ensureArchive(PROTON_ARCHIVE_PATH, PROTON_DB_PATH, { clean: false });
			}
			lockRuntimeDir();
			freezeRuntimeDir();
			loadVpnIpsCache();
			loadProtonAddon();
		} catch (error) {
			console.error("[security] ❌ Failed to restore VPN runtime directory", error);
		}
	}, 30000);
	if (typeof runtimeGuardInterval.unref === "function") {
		runtimeGuardInterval.unref();
	}
}

function prepareVpnRuntime() {
	const mainOk = ensureArchive(VPN_ARCHIVE_PATH, VPN_DB_PATH, { clean: true });
	if (!mainOk) {
		throw new Error(`VPN archive missing at ${VPN_ARCHIVE_PATH}`);
	}
	if (fs.existsSync(PROTON_ARCHIVE_PATH)) {
		ensureArchive(PROTON_ARCHIVE_PATH, PROTON_DB_PATH, { clean: false });
	} else {
		console.warn("[security] ⚠️ Proton addon archive not found; continuing without detailed Proton metadata.");
	}
	lockRuntimeDir();
	freezeRuntimeDir();
	startRuntimeGuard();
}

function cleanupRuntimeArtifacts() {
	if (!VPN_DETECTION_ENABLED) {
		return;
	}
	if (runtimeGuardInterval) {
		clearInterval(runtimeGuardInterval);
		runtimeGuardInterval = null;
	}
	thawRuntimeDir();
	unlockRuntimeDir();
	try {
		fs.rmSync(RUNTIME_DIR, { recursive: true, force: true });
	} catch {
		// ignore
	}
}

let runtimeCleanupTriggered = false;
function cleanupRuntimeArtifactsSafe() {
	if (runtimeCleanupTriggered) {
		return;
	}
	runtimeCleanupTriggered = true;
	cleanupRuntimeArtifacts();
}
process.once("exit", cleanupRuntimeArtifactsSafe);

const shutdownController = createShutdownController({
	cleanup: cleanupRuntimeArtifactsSafe,
});

["SIGTERM", "SIGQUIT"].forEach((signalName) => {
	process.on(signalName, () => {
		void initiateShutdown(`${signalName} signal`);
	});
});

process.on("SIGINT", () => {
	if (interactiveConsoleEnabled) {
		console.log("[console] Ctrl+C is disabled. Type 'stop' to shut down.");
		if (consoleInterface) {
			consoleInterface.prompt();
		}
		return;
	}
	console.log("[console] Ctrl+C received; shutting down.");
	void initiateShutdown("SIGINT (Ctrl+C)");
});
// --- robust host parser: CSV | JSON[] -> Set(hosts) ---
function parseHosts(input, fallbackCSV = "") {
	const source =
		typeof input === "string" && input.trim() ? input.trim() : fallbackCSV;
	let entries = null;

	// Try JSON first: '["tweb.host","tele.host"]'
	if (source.startsWith("[") && source.endsWith("]")) {
		try {
			const parsed = JSON.parse(source);
			if (Array.isArray(parsed)) entries = parsed;
		} catch {
			// ignore JSON parse failures, will fall back to CSV below
		}
	}
	// Fallback CSV: 'tweb.host, tele.host'
	if (!entries) {
		entries = source.split(/[,\s]+/);
	}

	return new Set(
		entries
			.map((value) => String(value || "").trim().toLowerCase())
			.filter(Boolean),
	);
}

const LOGIN_CONFIG_PLACEHOLDER = "<!--LOGIN_CONFIG_SCRIPT-->";
const LOGIN_NOSCRIPT_PLACEHOLDER = "<!--GTM_NOSCRIPT-->";

function sanitizeGtmId(value) {
	if (typeof value !== "string") return "";
	const trimmed = value.trim();
	if (!trimmed) return "";
	return trimmed.replace(/[^0-9A-Za-z_-]/g, "");
}

function buildLoginConfigScript(config) {
	const payload = JSON.stringify(config ?? {});
	return `<script>window.__LOGIN_PAGE_CONFIG__=Object.freeze(${payload});</script>`;
}

function buildGtmNoscriptSnippet(gtmId) {
	const safeId = sanitizeGtmId(gtmId);
	if (!safeId) return "";
	return `<noscript><iframe src="https://www.googletagmanager.com/ns.html?id=${safeId}" height="0" width="0" style="display:none;visibility:hidden"></iframe></noscript>`;
}

function buildLoginPageHtml() {
	const runtimeConfig = {
		turnstileSiteKey: TURNSTILE_SITE_KEY,
		gtmId: GTM_CONTAINER_ID,
	};
	const script = buildLoginConfigScript(runtimeConfig);
	const noscript = buildGtmNoscriptSnippet(runtimeConfig.gtmId);
	return LOGIN_HTML_TEMPLATE.replace(LOGIN_CONFIG_PLACEHOLDER, script).replace(
		LOGIN_NOSCRIPT_PLACEHOLDER,
		noscript,
	);
}

const LOGIN_PAGE_HTML = buildLoginPageHtml();

function getFirstHost(hostSet) {
	for (const host of hostSet) {
		if (host) {
			return host;
		}
	}
	return null;
}

const TWEB_HOSTS = parseHosts(process.env.TWEB_HOSTS);
const MAIN_HOSTS = parseHosts(process.env.MAIN_HOSTS);

console.log(
	`[security] Cloudflare proxy mode is ${
		USE_CF ? "ENABLED" : "DISABLED"
	}. Direct IP access is ${USE_CF ? "limited to Cloudflare edge" : "completely blocked"}.`,
);
console.log(
	`[security] TLS material loaded from cert=${TLS_CERT_PATH} key=${TLS_KEY_PATH}`,
);

if (!fs.existsSync(PUBLIC_CONFIG_PATH)) {
	try {
		if (fs.existsSync(DEFAULT_CONFIG_PATH)) {
			fs.copyFileSync(DEFAULT_CONFIG_PATH, PUBLIC_CONFIG_PATH);
			console.log(
				`[boot] public/config.json missing; copied default config from ${DEFAULT_CONFIG_PATH}`,
			);
		} else {
			console.warn(
				"[boot] Neither public/config.json nor config.default.json found. /config.json requests will fail until one is provided.",
			);
		}
	} catch (error) {
		console.error(
			`[boot] Failed to create public/config.json: ${
				error instanceof Error ? error.message : error
			}`,
		);
	}
}

let twebPackageManager = null;
if (fs.existsSync(TWEB_PACKAGE_JSON_PATH)) {
	try {
		const pkgRaw = fs.readFileSync(TWEB_PACKAGE_JSON_PATH, "utf8");
		const pkgJson = JSON.parse(pkgRaw || "{}");
		if (pkgJson && typeof pkgJson.packageManager === "string") {
			twebPackageManager = pkgJson.packageManager;
		}
	} catch (error) {
		console.warn(
			`[modules] Unable to inspect tweb/package.json: ${
				error instanceof Error ? error.message : error
			}`,
		);
	}
}


const twebNodeModulesPresent = fs.existsSync(TWEB_NODE_MODULES_DIR);
if (
	twebPackageManager &&
	twebPackageManager.startsWith("pnpm") &&
	fs.existsSync(TWEB_PACKAGE_JSON_PATH) &&
	!twebNodeModulesPresent
) {
	console.warn(
		"[modules] TWeb dependencies not installed. Run `pnpm install --prod` inside server/tweb before enabling the Telegram module.",
	);
}

const availableModules = [];
let createTwebAppFactory = null;
const TWEB_MODULE_ENTRY = path.join(__dirname, "tweb", "app.mjs");

if (fs.existsSync(TWEB_MODULE_ENTRY)) {
	try {
		const mod = await import("./tweb/app.mjs");
		if (mod && typeof mod.createTwebApp === "function") {
			createTwebAppFactory = mod.createTwebApp;
			availableModules.push("Telegram");
		} else {
			console.warn(
				"[modules] Telegram module is present but does not export createTwebApp(); skipping.",
			);
		}
	} catch (error) {
		console.error(
			`[modules] Failed to initialize Telegram module: ${error instanceof Error ? error.message : error}`,
		);
		if (twebPackageManager && twebPackageManager.startsWith("pnpm")) {
			console.error(
				"[modules] Make sure to install Telegram Web dependencies with `pnpm install --prod` inside server/tweb before starting the server.",
			);
		}
	}
}

if (!availableModules.length) {
	console.log("[modules] 🎛️ Running modules: NONE");
} else {
	console.log(`[modules] 🎛️ Running modules: ${availableModules.join(", ")}`);
}
console.log(
	VPN_DETECTION_ENABLED
		? "[security] 🧭 VPN detection is ENABLED"
		: "[security] 💤 VPN detection is DISABLED via environment",
);

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
	// Prioritize Cloudflare connecting IP (most reliable when using CF)
	const cfIp = req.headers["cf-connecting-ip"];
	if (typeof cfIp === "string" && cfIp.trim()) {
		return cfIp.trim();
	}
	
	// Fallback to X-Forwarded-For (first IP in chain)
	const forwarded = req.headers["x-forwarded-for"];
	if (typeof forwarded === "string" && forwarded.trim()) {
		return forwarded.split(",")[0].trim();
	}
	
	// Last resort - direct connection IP
	return req.ip || req.socket?.remoteAddress || "";
}

function getPeerIp(req) {
	return normalizeIpForLookup(req.socket?.remoteAddress || "");
}

function getRequestHost(req) {
	return (req.headers.host || "").replace(/:\d+$/, "").toLowerCase();
}

function isCloudflareIp(ip) {
	if (!ip) return false;
	const ipv4Int = ipv4ToInt(ip);
	if (ipv4Int !== null) {
		return CLOUDFLARE_IPV4_RANGES.some(
			(range) => ipv4Int >= range.start && ipv4Int <= range.end,
		);
	}
	const ipv6Int = ipv6ToBigInt(ip);
	if (ipv6Int !== null) {
		return CLOUDFLARE_IPV6_RANGES.some(
			(range) => ipv6Int >= range.start && ipv6Int <= range.end,
		);
	}
	return false;
}

function isCloudflareRequest(req) {
	return isCloudflareIp(getPeerIp(req));
}

function isDirectIpAccess(req) {
	const host = getRequestHost(req);
	if (!host) {
		return true;
	}
	if (!DIRECT_IP_HOST_PATTERN.test(host)) {
		return false;
	}
	// Allow Cloudflare to hit the origin IP when CF is enabled so only CF can reach it.
	if (USE_CF && isCloudflareRequest(req)) {
		return false;
	}
	return true;
}

function ipv4ToInt(ip) {
	const parts = typeof ip === "string" ? ip.split(".") : [];
	if (parts.length !== 4) {
		return null;
	}
	let value = 0;
	for (const part of parts) {
		if (part === "" || part === undefined) return null;
		const octet = Number(part);
		if (!Number.isInteger(octet) || octet < 0 || octet > 255) {
			return null;
		}
		value = (value << 8) + octet;
	}
	return value >>> 0;
}

function parseIpv4Cidr(cidr) {
	if (typeof cidr !== "string") return null;
	const [base, prefixRaw] = cidr.split("/");
	const prefixLength = prefixRaw === undefined ? 32 : Number(prefixRaw);
	const baseInt = ipv4ToInt(base);
	if (baseInt === null) return null;
	if (
		Number.isNaN(prefixLength) ||
		prefixLength < 0 ||
		prefixLength > 32
	) {
		return null;
	}
	const normalizedBase = baseInt >>> 0;
	if (prefixLength === 0) {
		return { start: 0, end: 0xffffffff };
	}
	if (prefixLength === 32) {
		return { start: normalizedBase, end: normalizedBase };
	}
	const hostBits = 32 - prefixLength;
	const rangeSize = 2 ** hostBits;
	const start = (normalizedBase >>> hostBits) << hostBits;
	const end = (start + rangeSize - 1) >>> 0;
	return { start: start >>> 0, end };
}

function expandIpv6Parts(parts) {
	const result = [];
	for (const raw of parts) {
		const part = typeof raw === "string" ? raw.trim() : "";
		if (!part) {
			result.push("0");
			continue;
		}
		if (part.includes(".")) {
			const ipv4 = ipv4ToInt(part);
			if (ipv4 === null) {
				return null;
			}
			const high = ((ipv4 >>> 16) & 0xffff).toString(16);
			const low = (ipv4 & 0xffff).toString(16);
			result.push(high, low);
		} else {
			result.push(part);
		}
	}
	return result;
}

function normalizeIpv6Segments(ip) {
	if (typeof ip !== "string" || !ip.length) {
		return null;
	}
	if (ip.indexOf("::") !== ip.lastIndexOf("::")) {
		return null;
	}
	if (ip === "::") {
		return Array(8).fill("0");
	}
	const hasCompressed = ip.includes("::");
	let headParts = [];
	let tailParts = [];
	if (hasCompressed) {
		const [head, tail] = ip.split("::");
		headParts = head ? head.split(":") : [];
		tailParts = tail ? tail.split(":") : [];
	} else {
		headParts = ip.split(":");
		tailParts = [];
	}
	const head = expandIpv6Parts(headParts);
	const tail = expandIpv6Parts(tailParts);
	if (!head || !tail) {
		return null;
	}
	let segments;
	if (hasCompressed) {
		const missing = 8 - (head.length + tail.length);
		if (missing < 0) {
			return null;
		}
		segments = [...head, ...Array(missing).fill("0"), ...tail];
	} else {
		segments = head;
	}
	if (segments.length !== 8) {
		return null;
	}
	return segments.map((segment) => (segment && segment.length ? segment : "0"));
}

function normalizeIpForLookup(ip) {
	if (typeof ip !== "string") {
		return "";
	}
	let value = ip.trim();
	if (!value) {
		return "";
	}

	const zoneIndex = value.indexOf("%");
	if (zoneIndex !== -1) {
		value = value.slice(0, zoneIndex);
	}

	const dottedMapped = value.match(/^::ffff:(?:0:)?(\d{1,3}(?:\.\d{1,3}){3})$/i);
	if (dottedMapped) {
		return dottedMapped[1];
	}

	const segments = normalizeIpv6Segments(value);
	if (segments) {
		const mapped =
			segments.slice(0, 5).every((segment) => segment === "0") &&
			(segments[5] || "").toLowerCase() === "ffff";
		if (mapped) {
			const high = parseInt(segments[6], 16);
			const low = parseInt(segments[7], 16);
			if (!Number.isNaN(high) && !Number.isNaN(low)) {
				return [
					(high >> 8) & 0xff,
					high & 0xff,
					(low >> 8) & 0xff,
					low & 0xff,
				].join(".");
			}
		}
	}

	return value;
}

function ipv6ToBigInt(ip) {
	const segments = normalizeIpv6Segments(ip);
	if (!segments) {
		return null;
	}
	let value = 0n;
	for (const segment of segments) {
		const parsed = parseInt(segment, 16);
		if (Number.isNaN(parsed) || parsed < 0 || parsed > 0xffff) {
			return null;
		}
		value = (value << 16n) + BigInt(parsed);
	}
	return value;
}

function parseIpv6Cidr(cidr) {
	if (typeof cidr !== "string") return null;
	const [base, prefixRaw] = cidr.split("/");
	const prefixLength = prefixRaw === undefined ? 128 : Number(prefixRaw);
	if (
		Number.isNaN(prefixLength) ||
		prefixLength < 0 ||
		prefixLength > 128
	) {
		return null;
	}
	const baseInt = ipv6ToBigInt(base);
	if (baseInt === null) {
		return null;
	}
	if (prefixLength === 128) {
		return { start: baseInt, end: baseInt };
	}
	if (prefixLength === 0) {
		const max = (1n << 128n) - 1n;
		return { start: 0n, end: max };
	}
	const hostBits = 128 - prefixLength;
	const shift = BigInt(hostBits);
	const start = (baseInt >> shift) << shift;
	const end = start + (1n << shift) - 1n;
	return { start, end };
}

function binarySearchExact32(values, providers, target) {
	let low = 0;
	let high = values.length - 1;
	while (low <= high) {
		const mid = (low + high) >> 1;
		const current = values[mid];
		if (current === target) {
			return providers[mid];
		}
		if (current < target) {
			low = mid + 1;
		} else {
			high = mid - 1;
		}
	}
	return -1;
}

function binarySearchExact128(values, providers, target) {
	let low = 0;
	let high = values.length - 1;
	while (low <= high) {
		const mid = (low + high) >> 1;
		const current = values[mid];
		if (current === target) {
			return providers[mid];
		}
		if (current < target) {
			low = mid + 1;
		} else {
			high = mid - 1;
		}
	}
	return -1;
}

function findProviderInRanges32(value, ranges) {
	const { start, end, providers } = ranges;
	let low = 0;
	let high = start.length - 1;
	while (low <= high) {
		const mid = (low + high) >> 1;
		if (value < start[mid]) {
			high = mid - 1;
		} else if (value > end[mid]) {
			low = mid + 1;
		} else {
			return providers[mid];
		}
	}
	return -1;
}

function findProviderInRanges128(value, ranges) {
	const { start, end, providers } = ranges;
	let low = 0;
	let high = start.length - 1;
	while (low <= high) {
		const mid = (low + high) >> 1;
		if (value < start[mid]) {
			high = mid - 1;
		} else if (value > end[mid]) {
			low = mid + 1;
		} else {
			return providers[mid];
		}
	}
	return -1;
}

function readUint128BE(buffer, offset) {
	let value = 0n;
	for (let i = 0; i < 16; i += 1) {
		value = (value << 8n) | BigInt(buffer[offset + i]);
	}
	return value;
}

function parseVpnBinary(buffer) {
	let offset = 0;
	const ensure = (bytes) => {
		if (offset + bytes > buffer.length) {
			throw new Error("VPN database file is truncated");
		}
	};
	const readUint8 = () => {
		ensure(1);
		const value = buffer.readUInt8(offset);
		offset += 1;
		return value;
	};
	const readUint16 = () => {
		ensure(2);
		const value = buffer.readUInt16LE(offset);
		offset += 2;
		return value;
	};
	const readUint32 = () => {
		ensure(4);
		const value = buffer.readUInt32LE(offset);
		offset += 4;
		return value;
	};
	const readUint128 = () => {
		ensure(16);
		const value = readUint128BE(buffer, offset);
		offset += 16;
		return value;
	};
	const readString = () => {
		const length = readUint16();
		ensure(length);
		const str = buffer.toString("utf8", offset, offset + length);
		offset += length;
		return str;
	};

	ensure(4);
	const magic = buffer.toString("ascii", offset, offset + 4);
	offset += 4;
	if (magic !== "VPDB") {
		throw new Error("Unsupported VPN DB format");
	}
	const version = readUint8();
	offset += 3; // reserved bytes
	if (version !== 1) {
		throw new Error(`Unsupported VPN DB version ${version}`);
	}

	const providerCount = readUint32();
	const ipv4ExactCount = readUint32();
	const ipv4RangeCount = readUint32();
	const ipv6ExactCount = readUint32();
	const ipv6RangeCount = readUint32();

	const providers = new Array(providerCount);
	for (let i = 0; i < providerCount; i += 1) {
		providers[i] = readString();
	}
	if (!providers.length) {
		providers.push("unknown");
	}

	const ipv4ExactValues = new Uint32Array(ipv4ExactCount);
	const ipv4ExactProviders = new Uint16Array(ipv4ExactCount);
	for (let i = 0; i < ipv4ExactCount; i += 1) {
		ipv4ExactValues[i] = readUint32();
		ipv4ExactProviders[i] = readUint16();
	}

	const ipv4RangeStart = new Uint32Array(ipv4RangeCount);
	const ipv4RangeEnd = new Uint32Array(ipv4RangeCount);
	const ipv4RangeProviders = new Uint16Array(ipv4RangeCount);
	for (let i = 0; i < ipv4RangeCount; i += 1) {
		ipv4RangeStart[i] = readUint32();
		ipv4RangeEnd[i] = readUint32();
		ipv4RangeProviders[i] = readUint16();
	}

	const ipv6ExactValues = new Array(ipv6ExactCount);
	const ipv6ExactProviders = new Uint16Array(ipv6ExactCount);
	for (let i = 0; i < ipv6ExactCount; i += 1) {
		ipv6ExactValues[i] = readUint128();
		ipv6ExactProviders[i] = readUint16();
	}

	const ipv6RangeStart = new Array(ipv6RangeCount);
	const ipv6RangeEnd = new Array(ipv6RangeCount);
	const ipv6RangeProviders = new Uint16Array(ipv6RangeCount);
	for (let i = 0; i < ipv6RangeCount; i += 1) {
		ipv6RangeStart[i] = readUint128();
		ipv6RangeEnd[i] = readUint128();
		ipv6RangeProviders[i] = readUint16();
	}

	return {
		providers,
		ipv4Exact: {
			values: ipv4ExactValues,
			providers: ipv4ExactProviders,
		},
		ipv4Ranges: {
			start: ipv4RangeStart,
			end: ipv4RangeEnd,
			providers: ipv4RangeProviders,
		},
		ipv6Exact: {
			values: ipv6ExactValues,
			providers: ipv6ExactProviders,
		},
		ipv6Ranges: {
			start: ipv6RangeStart,
			end: ipv6RangeEnd,
			providers: ipv6RangeProviders,
		},
		stats: {
			ipv4Exact: ipv4ExactCount,
			ipv4Ranges: ipv4RangeCount,
			ipv6Exact: ipv6ExactCount,
			ipv6Ranges: ipv6RangeCount,
		},
	};
}

function loadVpnIpsCache() {
	try {
		const stats = fs.statSync(VPN_DB_PATH);
		if (stats.mtimeMs !== vpnCacheMTime) {
			const buffer = fs.readFileSync(VPN_DB_PATH);
			vpnData = parseVpnBinary(buffer);
			vpnCacheMTime = stats.mtimeMs;
			vpnCacheMissingLogged = false;
			const totalExact = vpnData.stats.ipv4Exact + vpnData.stats.ipv6Exact;
			const totalRanges = vpnData.stats.ipv4Ranges + vpnData.stats.ipv6Ranges;
			console.log(
				`[security] 🛡️ Loaded VPN database (${formatInteger(totalExact)} exact IPs, ${formatInteger(totalRanges)} ranges, ${formatInteger(vpnData.providers.length)} providers)`,
			);
		}
	} catch (error) {
		if (error.code === "ENOENT") {
			if (!vpnCacheMissingLogged) {
				console.warn(`[security] ⚠️ VPN DB file not found at ${VPN_DB_PATH}. VPN blocking disabled.`);
				vpnCacheMissingLogged = true;
			}
		} else {
			console.error(`[security] ❌ Failed to load VPN data: ${error.message}`);
		}
		vpnData = createEmptyVpnData();
		vpnCacheMTime = 0;
	}
	return vpnData;
}

function loadProtonAddon() {
	protonAddon.byIp = new Map();
	protonAddon.enabled = false;
	protonAddon.generatedAt = null;
	try {
		const raw = fs.readFileSync(PROTON_DB_PATH, "utf8");
		const data = JSON.parse(raw);
		const map = new Map();
		for (const record of data.records || []) {
			const ip = (record.ip || "").trim();
			if (!ip) {
				continue;
			}
			map.set(ip, {
				server: record.server || null,
				city: record.city || null,
				country: record.country || null,
				tier: typeof record.tier === "number" ? record.tier : null,
			});
		}
		protonAddon.byIp = map;
		protonAddon.enabled = map.size > 0;
		protonAddon.generatedAt = data.generated_at || null;
		if (protonAddon.enabled) {
			console.log(`[security] 🧪 Loaded Proton addon metadata for ${formatInteger(map.size)} IPs.`);
		}
	} catch (error) {
		if (error.code !== "ENOENT") {
			console.error(`[security] ❌ Failed to load Proton addon: ${error.message || error}`);
		}
		protonAddon.byIp = new Map();
		protonAddon.enabled = false;
	}
}

function getProtonMetadataForIp(ip) {
	if (!VPN_DETECTION_ENABLED || !protonAddon.enabled) {
		return null;
	}
	const normalized = normalizeIpForLookup(ip);
	if (!normalized) {
		return null;
	}
	return protonAddon.byIp.get(normalized) || null;
}

function stringifyForInlineScript(value) {
	return JSON.stringify(value).replace(/</g, "\\u003c");
}

function renderVpnBlockedPage(res, provider, protonMeta) {
	let html;
	try {
		if (!vpnBlockedTemplate) {
			vpnBlockedTemplate = fs.readFileSync(VPN_BLOCKED_HTML_PATH, "utf8");
		}
		html = vpnBlockedTemplate;
	} catch (error) {
		console.error("[security] ❌ Failed to read VPN blocked HTML:", error);
		res.status(403).type("text/plain").send("VPN access not allowed");
		return;
	}
	const safeProvider = (provider || "a VPN").replace(/'/g, "\\'");
	const metaJson = stringifyForInlineScript(protonMeta || null);
	const finalHtml = html.replace(/{{PROVIDER}}/g, safeProvider).replace("{{PROTON_META}}", metaJson);
	if (typeof res.status === "function" && typeof res.set === "function" && typeof res.send === "function") {
		res.status(403).set("Content-Type", "text/html; charset=utf-8").send(finalHtml);
	} else {
		res.statusCode = 403;
		res.setHeader("Content-Type", "text/html; charset=utf-8");
		res.end(finalHtml);
	}
}

function isVpnIp(ip) {
	if (!VPN_DETECTION_ENABLED) {
		return false;
	}
	const normalizedIp = normalizeIpForLookup(ip);
	if (!normalizedIp) {
		return false;
	}
	const vpnDataCache = loadVpnIpsCache();
	let providerIndex = -1;

	if (normalizedIp.includes(":")) {
		const numeric = ipv6ToBigInt(normalizedIp);
		if (numeric === null) {
			return false;
		}
		providerIndex = binarySearchExact128(
			vpnDataCache.ipv6Exact.values,
			vpnDataCache.ipv6Exact.providers,
			numeric,
		);
		if (providerIndex < 0) {
			providerIndex = findProviderInRanges128(numeric, vpnDataCache.ipv6Ranges);
		}
	} else {
		const numeric = ipv4ToInt(normalizedIp);
		if (numeric === null) {
			return false;
		}
		providerIndex = binarySearchExact32(
			vpnDataCache.ipv4Exact.values,
			vpnDataCache.ipv4Exact.providers,
			numeric,
		);
		if (providerIndex < 0) {
			providerIndex = findProviderInRanges32(numeric, vpnDataCache.ipv4Ranges);
		}
	}

	if (providerIndex < 0) {
		return false;
	}

	return vpnDataCache.providers[providerIndex] || "unknown";
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

const securityHeadersMiddleware = (req, res, next) => {
	res.header("Cross-Origin-Embedder-Policy", "require-corp");
	res.header("Access-Control-Allow-Origin", "*");
	res.header("Cross-Origin-Opener-Policy", "same-origin");
	res.header("Cross-Origin-Resource-Policy", "same-site");
	res.header("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload");
	next();
};

const vpnBlockingMiddleware = (req, res, next) => {
	if (!VPN_DETECTION_ENABLED) {
		return next();
	}
	// Block direct IP access (not via Cloudflare)
	if (isDirectIpAccess(req)) {
		console.warn(`[security] Blocked direct IP access from ${getClientIp(req)}`);
		renderDirectIpBlockedPage(res);
		return;
	}
	
	// Check for VPN IPs
	const clientIp = getClientIp(req);
	if (clientIp) {
		const vpnProvider = isVpnIp(clientIp);
		if (vpnProvider) {
			console.warn(`[security] Blocked VPN IP: ${clientIp} (${vpnProvider})`);
			const protonMeta = getProtonMetadataForIp(clientIp);
			renderVpnBlockedPage(res, vpnProvider, protonMeta);
			return;
		}
	}
	
	next();
};

function attachSessionMiddleware(req, _res, next) {
	const token = getCookieValue(req, COOKIE_NAME);
	const session = validateSession(token);
	if (session) {
		req.user = { username: session.username };
	} else {
		req.user = null;
	}
	next();
}

function registerLoginRoutes(app) {
		app.get("/login", (req, res) => {
			if (req.user) {
				const target = safeRedirectTarget(req.query.next);
				return res.redirect(target);
			}
			res.setHeader("Cache-Control", "no-store");
			res.type("html").send(LOGIN_PAGE_HTML);
		});

	app.post("/login", async (req, res) => {
		const body = req.body || {};
		const { username, password, next: nextRaw } = body;
		const nextTarget = safeRedirectTarget(nextRaw);
		const nextSuffix =
			nextTarget !== "/" ? `&next=${encodeURIComponent(nextTarget)}` : "";
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
}

function createAuthGuard({ openPaths, openPrefixes }) {
	const allowedPaths = openPaths instanceof Set ? openPaths : new Set(openPaths || []);
	const allowedPrefixes = Array.isArray(openPrefixes) ? openPrefixes : [];
	return function authGuard(req, res, next) {
		if (req.user) return next();
		if (allowedPaths.has(req.path)) return next();
		if (allowedPrefixes.some((prefix) => req.path.startsWith(prefix))) {
			return next();
		}
		if (req.method === "GET" || req.method === "HEAD") {
			const target = safeRedirectTarget(req.originalUrl || "/");
			const suffix =
				target !== "/" ? `?next=${encodeURIComponent(target)}` : "";
			res.redirect(302, `/login${suffix}`);
			return;
		}
		res.status(401).json({ error: "Authentication required" });
	};
}

function createRateLimitMiddleware({ windowMs, maxRequests }) {
	const buckets = new Map();
	const cleanupInterval = setInterval(() => {
		const cutoff = Date.now() - windowMs * 2;
		for (const [ip, bucket] of buckets) {
			if (bucket.windowStart < cutoff) {
				buckets.delete(ip);
			}
		}
	}, windowMs);
	if (typeof cleanupInterval.unref === "function") {
		cleanupInterval.unref();
	}
	return function rateLimit(req, res, next) {
		const clientIp = getClientIp(req) || "unknown";
		const now = Date.now();
		let bucket = buckets.get(clientIp);
		if (!bucket) {
			bucket = { windowStart: now, count: 0 };
			buckets.set(clientIp, bucket);
		}
		if (now - bucket.windowStart >= windowMs) {
			bucket.windowStart = now;
			bucket.count = 0;
		}
		bucket.count += 1;
		if (bucket.count > maxRequests) {
			renderDirectIpBlockedPage(
				res,
				"Firewall-chan slowed you down. Please wait a moment and try again.",
				429,
			);
			return;
		}
		next();
	};
}

const localRateLimitMiddleware = ENABLE_LOCAL_DDOS_GUARD
	? createRateLimitMiddleware({
			windowMs: RATE_LIMIT_WINDOW_MS,
			maxRequests: RATE_LIMIT_MAX_REQUESTS,
		})
	: null;

function createProtectedHostApp({ openPaths = AUTH_OPEN_PATHS, openPrefixes = AUTH_OPEN_PREFIXES } = {}) {
	const app = express();
	app.set("trust proxy", true);
	app.set("etag", false);
	if (localRateLimitMiddleware) {
		app.use(localRateLimitMiddleware);
	}
	app.use(securityHeadersMiddleware);
	app.use(vpnBlockingMiddleware); // Add VPN blocking before everything else
	app.use(express.urlencoded({ extended: false }));
	app.use(attachSessionMiddleware);
	registerLoginRoutes(app);
	app.use(createAuthGuard({ openPaths, openPrefixes }));
	return app;
}

// Debug a local app folder and mount it to /apps, patching config.json to force load it
const debugAppFolder = process.env.DEBUG_APP_FOLDER;
console.log(
	`[debug] 🧪 App debugging is ${debugAppFolder ? "ENABLED" : "DISABLED"} for this run`,
);

const mainApp = createProtectedHostApp({
	openPaths: AUTH_OPEN_PATHS,
	openPrefixes: AUTH_OPEN_PREFIXES,
});
let twebContentApp;
if (createTwebAppFactory) {
	twebContentApp = createTwebAppFactory();
} else {
	const unavailableRouter = express.Router();
	unavailableRouter.use((req, res) => {
		res
			.status(503)
			.type("text/plain; charset=utf-8")
			.send("Telegram module is unavailable in this deployment.");
	});
	twebContentApp = unavailableRouter;
}
const twebHostApp = createProtectedHostApp({
	openPaths: TWEB_AUTH_OPEN_PATHS,
	openPrefixes: TWEB_AUTH_OPEN_PREFIXES,
});
twebHostApp.use(twebContentApp);
const mainDispatcher = createMainDispatcher({
	allowTwebHosts: !USE_SEPARATE_TWEB_PORT,
});
const twebDispatcher = USE_SEPARATE_TWEB_PORT ? createTwebDispatcher() : null;

// === VHOST DISPATCH ===
function enforceEdgeGuards(req, res) {
	if (isDirectIpAccess(req)) {
		console.warn(`[security] Blocked direct IP access from ${getClientIp(req)} at vhost level`);
		renderDirectIpBlockedPage(res);
		return true;
	}
	if (USE_CF && !isCloudflareRequest(req)) {
		console.warn(
			`[security] Blocked non-Cloudflare request from ${getPeerIp(req) || "unknown"} while USE_CF=true`,
		);
		renderDirectIpBlockedPage(
			res,
			"Firewall-chan only trusts Cloudflare shields right now.",
		);
		return true;
	}
	const clientIp = getClientIp(req);
	const vpnProvider = VPN_DETECTION_ENABLED && clientIp ? isVpnIp(clientIp) : false;
	if (vpnProvider) {
		console.warn(`[security] Blocked VPN IP: ${clientIp} (${vpnProvider}) at vhost level`);
		const protonMeta = getProtonMetadataForIp(clientIp);
		renderVpnBlockedPage(res, vpnProvider, protonMeta);
		return true;
	}
	return false;
}

function respondUnknownHost(res, message = "Unknown vhost") {
	res.statusCode = 421;
	res.setHeader("Content-Type", "text/plain; charset=utf-8");
	res.end(message);
}

function createMainDispatcher({ allowTwebHosts }) {
	return function mainDispatcher(req, res, next) {
		if (enforceEdgeGuards(req, res)) {
			return;
		}
		const host = (req.headers.host || "").replace(/:\d+$/, "").toLowerCase();
		if (allowTwebHosts && TWEB_HOSTS.has(host)) {
			return twebHostApp(req, res, next);
		}
		if (!allowTwebHosts && TWEB_HOSTS.has(host)) {
			respondUnknownHost(
				res,
				`Telegram hosts listen on HTTPS port ${TWEB_HTTPS_PORT}.`,
			);
			return;
		}
		if (MAIN_HOSTS.size && !MAIN_HOSTS.has(host)) {
			respondUnknownHost(res);
			return;
		}
		return mainApp(req, res, next);
	};
}

function createTwebDispatcher() {
	return function twebDispatcher(req, res, next) {
		if (enforceEdgeGuards(req, res)) {
			return;
		}
		const host = (req.headers.host || "").replace(/:\d+$/, "").toLowerCase();
		if (TWEB_HOSTS.size === 0) {
			respondUnknownHost(
				res,
				"Telegram module hostnames are not configured. Run ir_modules.sh.",
			);
			return;
		}
		if (TWEB_HOSTS.has(host)) {
			return twebHostApp(req, res, next);
		}
		respondUnknownHost(
			res,
			"Telegram module expects one of the configured hostnames.",
		);
	};
}
// --- Debug app passthrough ---
if (debugAppFolder) {
	mainApp.use((req, res, next) => {
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

	mainApp.use(
		"/apps/anura-devserver-debug",
		express.static(path.resolve(debugAppFolder)),
	);
}

// --- Static mounts ---
if (fs.existsSync(OPEN_DIR)) {
	mainApp.use("/open", express.static(OPEN_DIR));
} else {
	console.log(
		`[auth] Optional public directory not found at ${OPEN_DIR}. Create it to serve /open assets.`,
	);
}
mainApp.use(express.static(path.join(ROOT_DIR, "public")));
mainApp.use(express.static(path.join(ROOT_DIR, "build")));
mainApp.use("/bin", express.static(path.join(ROOT_DIR, "bin")));
mainApp.use("/apps", express.static(path.join(ROOT_DIR, "apps")));
mainApp.use(express.static(path.join(ROOT_DIR, "aboutproxy", "static")));

if (VPN_DETECTION_ENABLED) {
	try {
		prepareVpnRuntime();
		loadVpnIpsCache();
		loadProtonAddon();
		console.log("[security] 🟢 VPN database ready; continuing with server startup.");
	} catch (error) {
		console.error(
			`[security] ❌ Failed to prepare VPN database: ${error instanceof Error ? error.message : error}`,
		);
		process.exit(1);
	}
} else {
	console.log("[security] 💤 Skipping VPN DB preparation (disabled).");
}

const privilegeDropTracker = {
	pending: 0,
	dropped: false,
};

function trackServerForPrivilegeDrop(server) {
	if (!SHOULD_DROP_ROOT || !server) {
		return;
	}
	privilegeDropTracker.pending += 1;
	server.once("listening", () => {
		privilegeDropTracker.pending -= 1;
		if (privilegeDropTracker.pending <= 0 && !privilegeDropTracker.dropped) {
			dropRootPrivileges();
		}
	});
}

function dropRootPrivileges() {
	if (!SHOULD_DROP_ROOT || privilegeDropTracker.dropped) {
		return;
	}
	try {
		if (typeof process.setgid === "function") {
			process.setgid(DROP_PRIVS_GROUP);
		}
		if (typeof process.setuid === "function") {
			process.setuid(DROP_PRIVS_USER);
		}
		privilegeDropTracker.dropped = true;
		console.log(
			`[security] Dropped root privileges to ${DROP_PRIVS_USER}:${DROP_PRIVS_GROUP}`,
		);
	} catch (error) {
		console.error(
			`[security] Failed to drop root privileges: ${
				error instanceof Error ? error.message : error
			}`,
		);
		process.exit(1);
	}
}

function hardenHttpServer(server) {
	if (!server) return;
	server.keepAliveTimeout = 5000;
	server.headersTimeout = 10000;
	server.requestTimeout = 15000;
	server.on("connection", (socket) => {
		socket.setNoDelay(true);
		socket.setTimeout(20000, () => socket.destroy());
	});
	server.on("clientError", (err, socket) => {
		if (socket.writable) {
			socket.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
		}
		socket.destroy();
	});
}

// --- TLS material selection ---
function loadHttpsOptions() {
	try {
		return {
			key: fs.readFileSync(TLS_KEY_PATH),
			cert: fs.readFileSync(TLS_CERT_PATH),
		};
	} catch (error) {
		console.error(
			`[tls] Failed to read TLS files: ${
				error instanceof Error ? error.message : error
			}`,
		);
		process.exit(1);
	}
}

const httpsOptions = loadHttpsOptions();

// --- HTTPS primary ---
const httpsServer = https.createServer(httpsOptions, mainDispatcher);
hardenHttpServer(httpsServer);
shutdownController.track(httpsServer, "HTTPS");
httpsServer.listen(HTTPS_PORT, () => {
	console.log(
		`[server] 🚀 Main HTTPS listening on :${HTTPS_PORT} (${USE_CF ? "Cloudflare origin" : "direct"})`,
	);
	ensureInteractiveConsoleReady();
});
trackServerForPrivilegeDrop(httpsServer);

let twebHttpsServer = null;
if (USE_SEPARATE_TWEB_PORT && twebDispatcher) {
	twebHttpsServer = https.createServer(httpsOptions, twebDispatcher);
	hardenHttpServer(twebHttpsServer);
	shutdownController.track(twebHttpsServer, "Telegram HTTPS");
	twebHttpsServer.listen(TWEB_HTTPS_PORT, () => {
		console.log(
			`[server] 💬 Telegram HTTPS listening on :${TWEB_HTTPS_PORT} (dedicated Cloudflare tunnel)`,
		);
	});
	trackServerForPrivilegeDrop(twebHttpsServer);
}

// WISP over WSS
httpsServer.on("upgrade", (req, socket, head) => {
	if (isDirectIpAccess(req)) {
		console.warn(
			`[security] Blocked direct IP WSS access from ${getClientIp(req)}`,
		);
		socket.destroy();
		return;
	}
	if (USE_CF && !isCloudflareRequest(req)) {
		console.warn(
			`[security] Blocked non-Cloudflare WSS request from ${getPeerIp(req) || "unknown"}`,
		);
		socket.destroy();
		return;
	}
	const host = (req.headers.host || "").replace(/:\d+$/, "").toLowerCase();
	if (TWEB_HOSTS.has(host)) {
		return socket.destroy(); // or route to tweb WS if you have one
	}
	if (MAIN_HOSTS.size && !MAIN_HOSTS.has(host)) {
		return socket.destroy();
	}
	wisp.routeRequest(req, socket, head);
});

let httpRedirectServer = null;
	if (ENABLE_HTTP_REDIRECT) {
	httpRedirectServer = http.createServer((req, res) => {
			if (USE_CF && !isCloudflareRequest(req)) {
				renderDirectIpBlockedPage(
					res,
					"Cloudflare gateway is required for this origin.",
					403,
				);
				return;
			}
			if (isDirectIpAccess(req)) {
				renderDirectIpBlockedPage(res);
				return;
			}
		const hostCandidate =
			getRequestHost(req) ||
			getFirstHost(MAIN_HOSTS) ||
			getFirstHost(TWEB_HOSTS);
		if (!hostCandidate) {
			res
				.writeHead(421, {
					"Content-Type": "text/plain; charset=utf-8",
				})
				.end("No hostname configured");
			return;
		}
		const location = `https://${hostCandidate}${req.url || "/"}`;
		res.writeHead(301, {
			Location: location,
			"Content-Type": "text/plain; charset=utf-8",
		});
		res.end("Redirecting to HTTPS");
	});
hardenHttpServer(httpRedirectServer);
shutdownController.track(httpRedirectServer, "HTTP redirect");
httpRedirectServer.listen(HTTP_PORT, () => {
	console.log(`[server] ↪ HTTP redirector on :${HTTP_PORT} → HTTPS :${HTTPS_PORT}`);
});
trackServerForPrivilegeDrop(httpRedirectServer);
}

function ensureInteractiveConsoleReady() {
	if (!interactiveConsoleEnabled || consoleInterface) {
		return;
	}
	consoleInterface = startInteractiveConsole({
		onStop() {
			void initiateShutdown("console stop command");
		},
		shouldContinue: () => !shutdownController.isShuttingDown(),
	});
	installConsolePromptShim();
	refreshConsolePrompt();
}

function closeConsoleInterface() {
	if (!consoleInterface) {
		return;
	}
	consoleClosing = true;
	consoleInterface.close();
}

function startInteractiveConsole({ onStop, shouldContinue }) {
	const rl = readline.createInterface({
		input: process.stdin,
		output: process.stdout,
		terminal: true,
	});
	rl.setPrompt("> ");
	console.log(
		"[console] Type 'stop' to safely shut down. Ctrl+C is ignored in this mode.",
	);
	rl.on("line", (line) => {
		const trimmed = line.trim().toLowerCase();
		if (!trimmed) {
			if (shouldContinue()) {
				rl.prompt();
			}
			return;
		}
		if (trimmed === "stop") {
			onStop();
			return;
		}
		console.log(`[console] Unknown command: ${trimmed}`);
		if (shouldContinue()) {
			rl.prompt();
		}
	});
	rl.on("SIGINT", () => {
		if (shouldContinue()) {
			rl.prompt();
		}
	});
	rl.on("close", () => {
		if (!consoleClosing) {
			console.log(
				"[console] Input stream closed. Send SIGINT in non-interactive mode or type 'stop' next time to exit.",
			);
		}
		consoleClosing = false;
		consoleInterface = null;
	});
	rl.prompt();
	return rl;
}

function initiateShutdown(reason, exitCode = 0) {
	closeConsoleInterface();
	return shutdownController.request(reason, exitCode);
}

function createShutdownController({ cleanup } = {}) {
	const tracked = [];
	let shuttingDown = false;
	function track(server, label = "server") {
		if (!server || typeof server.close !== "function") {
			return;
		}
		tracked.push({ server, label });
	}
	function closeServer(entry) {
		return new Promise((resolve) => {
			try {
				entry.server.close((err) => {
					if (
						err &&
						err.code !== "ERR_SERVER_NOT_RUNNING" &&
						err.code !== "ERR_SERVER_NOT_LISTENING"
					) {
						console.error(
							`[server] Error closing ${entry.label}: ${
								err instanceof Error ? err.message : err
							}`,
						);
					}
					resolve();
				});
			} catch (error) {
				if (
					!(error && typeof error === "object" && error.code === "ERR_SERVER_NOT_RUNNING")
				) {
					console.error(
						`[server] Error closing ${entry.label}: ${
							error instanceof Error ? error.message : error
						}`,
					);
				}
				resolve();
			}
		});
	}
	async function request(reason = "shutdown", exitCode = 0) {
		if (shuttingDown) {
			return;
		}
		shuttingDown = true;
		console.log(`[server] 💘 Shutting down (${reason})...`);
		try {
			await Promise.all(tracked.map((entry) => closeServer(entry)));
		} catch (error) {
			console.error(
				`[server] Error while closing servers: ${
					error instanceof Error ? error.message : error
				}`,
			);
		}
		if (typeof cleanup === "function") {
			try {
				cleanup();
			} catch (error) {
				console.error(
					`[server] Cleanup error: ${error instanceof Error ? error.message : error}`,
				);
			}
		}
		console.log("[server] Shutdown complete. Goodbye 💘");
		process.exit(exitCode);
	}
	return {
		track,
		request,
		isShuttingDown: () => shuttingDown,
	};
}
