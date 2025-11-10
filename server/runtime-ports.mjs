import path from "path";
import { fileURLToPath } from "url";
import dotenv from "dotenv";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.join(__dirname, "..");

const ENV_PATHS = [
	{ path: path.join(ROOT_DIR, ".env"), override: false },
	{ path: path.join(__dirname, ".env"), override: true },
];

for (const candidate of ENV_PATHS) {
	try {
		dotenv.config({ path: candidate.path, override: candidate.override });
	} catch {
		// Missing .env files are fine; fall back to defaults.
	}
}

function parseBoolean(value, defaultValue = false) {
	if (value === undefined || value === null) return defaultValue;
	const normalized = String(value).trim().toLowerCase();
	if (!normalized) return defaultValue;
	return !["0", "false", "off", "no"].includes(normalized);
}

const useCf = parseBoolean(process.env.USE_CF ?? "true", true);
const enableHttpRedirect =
	!useCf || parseBoolean(process.env.ENABLE_HTTP_REDIRECT ?? "false", false);
const httpsPort = Number(process.env.HTTPS_PORT || (useCf ? 3433 : 443));
const httpPort = Number(process.env.HTTP_PORT || (useCf ? 8080 : 80));

const payload = {
	httpsPort,
	httpPort,
	enableHttpRedirect,
	useCf,
};

process.stdout.write(JSON.stringify(payload));
