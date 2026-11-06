import { readFile } from "node:fs/promises";

const lockfilePath: string = process.argv[2] ?? "";

if (!lockfilePath) {
console.error("Usage: npm run ci -- <path-to-package-lock.json>");
process.exit(1);
}

async function main() {
try {
const lockfileText = await readFile(lockfilePath, "utf8");
const lockfile = JSON.parse(lockfileText);

const response = await fetch("http://localhost:3000/scan-lockfile", {
method: "POST",
headers: {
"Content-Type": "application/json",
},
body: JSON.stringify(lockfile),
});

const result = (await response.json()) as {
status?: string;
message?: string;
policyFindings?: string[];
};

console.log("HTTP status:", response.status);
console.log("Scan status:", result.status ?? "UNKNOWN");

if (Array.isArray(result.policyFindings)) {
for (const finding of result.policyFindings) {
console.log("-", finding);
}
}

if (!response.ok || result.status !== "PASS") {
console.error("CI FAILED");
process.exitCode = 1;
return;
}

console.log("CI PASSED");
process.exitCode = 0;
} catch (error) {
console.error(
"CI ERROR:",
error instanceof Error ? error.message : error
);
process.exitCode = 1;
}
}

main();