import express from "express"; 
import { randomUUID } from "node:crypto";
import Ajv from "ajv";
import addFormats from "ajv-formats";
import cyclonedxSchema from "../schemas/bom-1.6.schema.json"
import spdxSchema from "../schemas/spdx.schema.json";
import jsfSchema from "../schemas/jsf-0.82.schema.json";

const ajv = new Ajv({
    allErrors: true,
    strict: false,
});

addFormats(ajv);

ajv.addSchema(spdxSchema);
ajv.addSchema(jsfSchema);
const validateSbom = ajv.compile(cyclonedxSchema);

const app = express();
app.use(express.json({
verify: (req, res, buf) => {
(req as express.Request & { rawBody?: Buffer }).rawBody = Buffer.from(buf);
},
}));

interface ScanHistoryEntry {
scanId: string;
status: string;
dependencyCount: number;
createdAt: string;
policyFindings: string[];
}

const scanHistory: ScanHistoryEntry[] = [];

interface ScanJob {
scanId: string;
status: "QUEUED" | "RUNNING" | "COMPLETED" | "FAILED";
createdAt: string;
result?: unknown;
error?: string;
}

const scanJobs = new Map<string, ScanJob>();

async function mapWithConcurrency<T, R>(
items: T[],
limit: number,
worker: (item: T, index: number) => Promise<R>
): Promise<R[]> {
const results: R[] = new Array(items.length);
let nextIndex = 0;

async function runWorker(): Promise<void> {
while (true) {
const currentIndex = nextIndex++;

if (currentIndex >= items.length) {
return;
}

const item = items[currentIndex];

if (item === undefined) {
return;
}

results[currentIndex] = await worker(item, currentIndex);
}
}

const workerCount = Math.min(limit, items.length);

await Promise.all(
Array.from({ length: workerCount }, () => runWorker())
);

return results;
}

const PORT = 3000;

const PACKAGE_AGE_COOLDOWN_DAYS = 7;

interface AllowListEntry {
name: string;
version: string;
reason: string;
expiresAt: string;
}

interface SecurityPolicy {
blockCritical: boolean;
blockHigh: boolean;
minimumPackageAgeDays: number;
allowList: AllowListEntry[];
}

const defaultPolicy: SecurityPolicy = {
blockCritical: true,
blockHigh: true,
minimumPackageAgeDays: 7,
allowList: [
{
name: "@hapi/pez",
version: "6.1.3",
reason: "Approved for the DepGuard allow-list demonstration.",
expiresAt: "2026-12-05T23:59:59.000Z",
},
],
};

async function evaluatePolicy(
dependencies: {
name: string;
version: string | null;
packageAgeDays: number | null;
ageCheckError: string | null;
warnings: string[];
vulnerabilities: unknown[];
}[],
policy: SecurityPolicy
) {
const findings: string[] = [];
let status: "PASS" | "FAIL" | "ERROR" = "PASS";

for (const dependency of dependencies) {
const packageName = dependency.name;
const packageVersion = dependency.version;

const allowed = policy.allowList.some(
(entry) =>
entry.name === packageName &&
entry.version === packageVersion &&
entry.reason.trim() !== "" &&
new Date(entry.expiresAt).getTime() > Date.now()
);

if (allowed) {
continue;
}

if (
policy.minimumPackageAgeDays > 0 &&
dependency.ageCheckError
) {
status = "ERROR";
findings.push(
`${packageName}: package age could not be verified.`
);
}

if (
policy.minimumPackageAgeDays > 0 &&
dependency.packageAgeDays !== null &&
dependency.packageAgeDays < policy.minimumPackageAgeDays
) {
if (status !== "ERROR") status = "FAIL";

findings.push(
`${packageName}: package is younger than ${policy.minimumPackageAgeDays} days.`
);
}

if (dependency.warnings.includes("Missing integrity field")) {
if (status !== "ERROR") status = "FAIL";
findings.push(`${packageName}: missing integrity field.`);
}

if (dependency.warnings.includes("Package has an install script")) {
if (status !== "ERROR") status = "FAIL";
findings.push(`${packageName}: has an install script.`);
}

if (
dependency.warnings.includes(
"Package uses a non-npm registry source"
)
) {
if (status !== "ERROR") status = "FAIL";
findings.push(`${packageName}: uses a non-npm registry source.`);
}

for (const vulnerability of dependency.vulnerabilities) {
 if (
 typeof vulnerability !== "object" ||
 vulnerability === null
 ) {
 continue;
 }

 const vuln = vulnerability as {
 id?: string;
 };

 if (!vuln.id) {
 status = "ERROR";
 findings.push(
 `${packageName}: vulnerability ID is missing.`
 );
 continue;
 }

 try {
 const fullAdvisory = await getOsvAdvisory(vuln.id);

 const advisory = fullAdvisory as {
 database_specific?: { severity?: string };
 severity?: { type?: string; score?: string }[];
 id?: string;
 };

 const severity = (
 advisory.database_specific?.severity ?? ""
 ).toUpperCase();

 if (
 (severity === "CRITICAL" && policy.blockCritical) ||
 (severity === "HIGH" && policy.blockHigh)
 ) {
 if (status !== "ERROR") status = "FAIL";

 findings.push(
 `${packageName}: ${severity} vulnerability ${vuln.id}.`
 );
 } else if (!severity) {
 status = "ERROR";
 findings.push(
 `${packageName}: severity could not be verified for ${vuln.id}.`
 );
 }
 } catch (error) {
 status = "ERROR";
 findings.push(
 `${packageName}: could not retrieve advisory ${vuln.id}.`
 );
 }
}
}

return {
status,
findings,
};
}

const osvCache = new Map<
string,
{
expiresAt: number;
result: unknown;
}
>();

const osvAdvisoryCache = new Map<
string,
{
expiresAt: number;
result: unknown;
}
>();


const OSV_CACHE_TTL = 24 * 60 * 60 * 1000;

async function getOsvAdvisory(advisoryId: string) {
 const cached = osvAdvisoryCache.get(advisoryId);

 if (cached && cached.expiresAt > Date.now()) {
 return cached.result;
 }

 const response = await fetch(
 `https://api.osv.dev/v1/vulns/${advisoryId}`
 );

 if (!response.ok) {
 throw new Error(
 `Could not retrieve OSV advisory ${advisoryId}: ${response.status}`
 );
 }

 const advisory = await response.json();

 osvAdvisoryCache.set(advisoryId, {
 expiresAt: Date.now() + OSV_CACHE_TTL,
 result: advisory,
 });

 return advisory;
}

const npmMetadataCache = new Map<
string,
{
expiresAt: number;
time: Record<string, string>;
}
>();

async function getPackagePublishedAt(
name: string,
version: string
): Promise<Date> {
let cached = npmMetadataCache.get(name);

if (!cached || cached.expiresAt <= Date.now()) {
const packageUrl =
`https://registry.npmjs.org/${encodeURIComponent(name)}`;

const response = await fetch(packageUrl);

if (!response.ok) {
throw new Error(
`Could not retrieve npm metadata for ${name}: ${response.status}`
);
}

const metadata = await response.json() as {
time?: Record<string, string>;
};

if (!metadata.time) {
throw new Error(`Publication dates unavailable for ${name}`);
}

cached = {
time: metadata.time,
expiresAt: Date.now() + 24 * 60 * 60 * 1000,
};

npmMetadataCache.set(name, cached);
}

const publishedAt = cached.time[version];

if (typeof publishedAt !== "string") {
throw new Error(
`Publication date not found for ${name}@${version}`
);
}

const publicationDate = new Date(publishedAt);

if (Number.isNaN(publicationDate.getTime())) {
throw new Error(
`Invalid publication date for ${name}@${version}`
);
}

return publicationDate;
}

async function checkOsvVulnerabilities(
 dependencies: { name: string; version: string }[]
) {
 const now = Date.now();

 const results = await Promise.all(
 dependencies.map(async (dependency) => {
 const key = `${dependency.name}@${dependency.version}`;

 const cached = osvCache.get(key);

 if (cached && cached.expiresAt > now) {
 console.log(`OSV CACHE HIT: ${key}`);
 return cached.result;
 }

 return null;
 })
 );

 const missingDependencies = dependencies.filter(
 (dependency, index) => results[index] === null
 );

 if (missingDependencies.length > 0) {
    console.log(`OSV FRESH REQUEST: ${missingDependencies.length} packages`);
    
 const response = await fetch("https://api.osv.dev/v1/querybatch", {
 method: "POST",
 headers: {
 "Content-Type": "application/json",
 },
 body: JSON.stringify({
 queries: missingDependencies.map((dependency) => ({
 package: {
 name: dependency.name,
 ecosystem: "npm",
 },
 version: dependency.version,
 })),
 }),
 });

 if (!response.ok) {
 throw new Error(`OSV.dev request failed: ${response.status}`);
 }

 const freshResults = await response.json() as {
 results?: unknown[];
 };

 const freshItems = freshResults.results ?? [];

 missingDependencies.forEach((dependency, index) => {
 const key = `${dependency.name}@${dependency.version}`;
 const result = freshItems[index] ?? { vulns: [] };

 osvCache.set(key, {
 result,
 expiresAt: Date.now() + OSV_CACHE_TTL,
 });

 const originalIndex = dependencies.findIndex(
 (item) =>
 item.name === dependency.name &&
 item.version === dependency.version
 );

 if (originalIndex !== -1) {
 results[originalIndex] = result;
 }
 });
 }

 return {
 results,
 };
}

function validateLockfileVersion(data: unknown): {
valid: boolean;
message: string;
} {
if (typeof data !== "object" || data === null || Array.isArray(data)) {
return {
        valid: false,
        message: "Lockfile must be a JSON object.",
};
}

const lockfile = data as Record<string, unknown>;

if (
lockfile.lockfileVersion !== 2 &&
lockfile.lockfileVersion !== 3
) {
return {
valid: false,
message: "Unsupported lockfile version. Only versions 2 and 3 are supported.",
};
}

return {
valid: true,
message: "Lockfile version is supported.",
};
}

app.use(express.json ({ limit: "10mb"}));
app.get("/", (_req, res) => {
    res.json({
        message: "welcome to depguard",
        status: "running",
    });
});
app.post("/test", (req, res) => {
    res.json({
        message: "DepGuard received your data!",
        receivedData: req.body,
  });
});
app.post("/validate-lockfile", (req, res) => {
const result = validateLockfileVersion(req.body);

if (!result.valid) {
return res.status(400).json(result);
}

return res.status(200).json(result);
});

app.post("/scan-lockfile", async (req, res) => {
const lockfile = req.body;

// First, check that the lockfile version is supported.
const validation = validateLockfileVersion(lockfile);

if (!validation.valid) {
return res.status(400).json(validation);
}

// Get the packages section from the lockfile.
const packages = lockfile.packages;

if (
typeof packages !== "object" ||
packages === null ||
Array.isArray(packages)
) {
return res.status(400).json({
error: "Lockfile must contain a valid packages object.",
});
}


// Collect package information without installing or running anything.

const dependencyEntries = Object.entries(packages).filter(
([path]) =>
typeof path === "string" &&
path.startsWith("node_modules/")
);

const dependencies = await mapWithConcurrency(
dependencyEntries,
5,
async ([path, details]) => {
const packageInfo = details as Record<string, unknown>;

const name = String(path).slice("node_modules/".length);

const version =
typeof packageInfo.version === "string"
? packageInfo.version
: null;

const resolved =
typeof packageInfo.resolved === "string"
? packageInfo.resolved
: null;

const isNonRegistrySource =
resolved !== null &&
!(
resolved.startsWith("https://registry.npmjs.org/") ||
resolved.startsWith("http://registry.npmjs.org/")
);

const warnings: string[] = [];

if (
typeof packageInfo.integrity !== "string" ||
packageInfo.integrity.trim() === ""
) {
warnings.push("Missing integrity field");
}

if (packageInfo.hasInstallScript === true) {
warnings.push("Package has an install script");
}

if (isNonRegistrySource) {
warnings.push("Package uses a non-npm registry source");
}

let publishedAt: string | null = null;
let packageAgeDays: number | null = null;
let ageCheckError: string | null = null;

if (version) {
try {
const publicationDate = await getPackagePublishedAt(
name,
version
);

publishedAt = publicationDate.toISOString();

packageAgeDays = Math.floor(
(Date.now() - publicationDate.getTime()) /
(1000 * 60 * 60 * 24)
);

if (packageAgeDays < PACKAGE_AGE_COOLDOWN_DAYS) {
warnings.push(
`Package version is younger than ${PACKAGE_AGE_COOLDOWN_DAYS} days`
);
}
} catch (error) {
ageCheckError =
error instanceof Error
? error.message
: "Package age check failed";

warnings.push("Package age could not be verified");
}
} else {
ageCheckError = "Package version is missing";
warnings.push("Package age could not be verified");
}

return {
path,
name,
version,
resolved: packageInfo.resolved ?? null,
integrity: packageInfo.integrity ?? null,
publishedAt,
packageAgeDays,
ageCheckError,
warnings,
};
}
);

const osvDependencies = dependencies
 .filter(
 (dependency) =>
 typeof dependency.version === "string" &&
 dependency.version.trim() !== ""
 )
 .map((dependency) => ({
 name: dependency.name,
 version: dependency.version as string,
 }));

const osvResults = await checkOsvVulnerabilities(osvDependencies);

const osvResultItems = (
 osvResults as {
 results?: Array<{ vulns?: unknown[] }>;
 }
).results ?? [];

const osvResultsByPackage = new Map<string, unknown[]>();

osvDependencies.forEach((dependency, index) => {
 const key = `${dependency.name}@${dependency.version}`;
 const vulnerabilities = osvResultItems[index]?.vulns ?? [];

 osvResultsByPackage.set(key, vulnerabilities);
});

const dependenciesWithVulnerabilities = dependencies.map((dependency) => {
 const key =
 typeof dependency.version === "string"
 ? `${dependency.name}@${dependency.version}`
 : "";

 return {
 ...dependency,
 vulnerabilities: osvResultsByPackage.get(key) ?? [],
 };
});

const sbomComponents = dependencies.map((dependency) => {
 const integrity =
 typeof dependency.integrity === "string"
 ? dependency.integrity
 : "";

const hashes = integrity.startsWith("sha512-")
? [
{
alg: "SHA-512",
content: Buffer.from(
integrity.replace("sha512-", ""),
"base64"
).toString("hex"),
},
]
: [];

 return {
 type: "library",
 name: dependency.name,
 version: dependency.version,
 purl: `pkg:npm/${dependency.name}@${dependency.version}`,
 hashes,
 };
});

const policyResult = await evaluatePolicy(
dependenciesWithVulnerabilities,
defaultPolicy
);

const sbom = {
 bomFormat: "CycloneDX",
 specVersion: "1.6",
 serialNumber: `urn:uuid:${randomUUID()}`,
 version: 1,
 components: sbomComponents,
};

const isSbomValid = validateSbom(sbom);

const sbomValidationErrors = validateSbom.errors ?? [];

const scanRecord: ScanHistoryEntry = {
scanId: randomUUID(),
status: policyResult.status,
dependencyCount: dependencies.length,
createdAt: new Date().toISOString(),
policyFindings: policyResult.findings,
};

scanHistory.push(scanRecord);

return res.status(200).json({
 message: "Lockfile scanned successfully.",
 status: policyResult.status,
 policyFindings: policyResult.findings,
 dependencyCount: dependencies.length,
 sbomComponents,
 sbom,
 sbomValide: isSbomValid,
 sbomValidationErrors,
 dependencies: dependenciesWithVulnerabilities,
 osvResults,
});
});

app.get("/scan-history", (_req, res) => {
return res.status(200).json({
totalScans: scanHistory.length,
scans: scanHistory,
});
});

app.post("/scan-async", (req, res) => {
const scanId = randomUUID();

const scanJob: ScanJob = {
scanId,
status: "QUEUED",
createdAt: new Date().toISOString(),
};

scanJobs.set(scanId, scanJob);

const lockfile = req.body;

res.status(202).json({
message: "Scan accepted and queued.",
scanId,
status: scanJob.status,
});

setImmediate(async () => {
const job = scanJobs.get(scanId);

if (!job) return;

job.status = "RUNNING";

try {
const scanResponse = await fetch(
`http://127.0.0.1:${PORT}/scan-lockfile`,
{
method: "POST",
headers: {
"Content-Type": "application/json",
},
body: JSON.stringify(lockfile),
}
);

const scanResult = await scanResponse.json();

if (!scanResponse.ok) {
job.status = "FAILED";
job.result = scanResult;
job.error = "Lockfile scan failed.";
return;
}

job.status = "COMPLETED";
job.result = scanResult;

} catch (error) {
job.status = "FAILED";
job.error =
error instanceof Error ? error.message : "Scan failed.";
}
});
});

app.get("/scan-status/:scanId", (req, res) => {
const { scanId } = req.params;

const job = scanJobs.get(scanId);

if (!job) {
return res.status(404).json({
error: "Scan not found.",
});
}

return res.status(200).json({
scanId: job.scanId,
status: job.status,
createdAt: job.createdAt,
});
});

app.get("/scan-results/:scanId", (req, res) => {
const { scanId } = req.params;

const job = scanJobs.get(scanId);

if (!job) {
return res.status(404).json({
error: "Scan not found.",
});
}

if (job.status !== "COMPLETED") {
return res.status(202).json({
message: "Scan results are not ready yet.",
scanId: job.scanId,
status: job.status,
});
}

return res.status(200).json({
scanId: job.scanId,
status: job.status,
result: job.result,
});
});

app.post("/scan-diff", (req, res) => {
 const { oldLockfile, newLockfile } = req.body;

 if (!oldLockfile || !newLockfile) {
 return res.status(400).json({
 error: "Both oldLockfile and newLockfile are required.",
 });
 }

 const oldPackages = oldLockfile.packages ?? {};
 const newPackages = newLockfile.packages ?? {};

 const added: string[] = [];
 const removed: string[] = [];
 const changed: string[] = [];

 for (const [name, newPackage] of Object.entries(newPackages)) {
 if (!(name in oldPackages)) {
 added.push(name || "root");
 } else {
 const oldPackage = oldPackages[name];

 if (oldPackage.version !== (newPackage as any).version) {
 changed.push(name || "root");
 }
 }
 }

 for (const name of Object.keys(oldPackages)) {
 if (!(name in newPackages)) {
 removed.push(name || "root");
 }
 }

 return res.status(200).json({
 added,
 removed,
 changed,
 summary: {
 added: added.length,
 removed: removed.length,
 changed: changed.length,
 },
 });
});

app.use((err: any, 
req: express.Request, 
res: express.Response, 
next: express.NextFunction) => {

if (err.type === "entity.too.large") {
return res.status(413).json({
error: "Request body is too large. Maximum allowed size is 10 MB.",
});
}

if (err instanceof SyntaxError && "body" in err) {
return res.status(400).json({
error: "Invalid JSON request body.",
});
}

console.error(err);

return res.status(500).json({
error: "An unexpected server error occurred.",
});
});





app.listen(PORT, () => {
    console.log(`DepGuard is running on port ${PORT}`);
});                                                                                                                                                                                                                                         