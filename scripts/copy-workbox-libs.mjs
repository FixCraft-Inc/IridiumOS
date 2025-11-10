#!/usr/bin/env node
import { copyWorkboxLibraries } from "workbox-build";
import path from "node:path";
import process from "node:process";

async function main() {
	const targetArg = process.argv[2] || "build/libs/workbox";
	const targetDir = path.resolve(process.cwd(), targetArg);
	try {
		const destPath = await copyWorkboxLibraries(targetDir);
		console.log(`[workbox] Copied libraries to ${destPath}`);
	} catch (error) {
		console.error("[workbox] Failed to copy libraries:", error);
		process.exitCode = 1;
	}
}

main();
