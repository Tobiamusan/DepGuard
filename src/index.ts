// ============================================================
// 1. IMPORTS
// ============================================================

// Express handles HTTP requests and API routes.
import express from "express";

// Crypto utilities for unique IDs and webhook signature verification.
import {
 randomUUID,
 createHmac,
 timingSafeEqual,
} from "node:crypto";

// AJV validates generated SBOM documents against JSON schemas.
import Ajv from "ajv";
import addFormats from "ajv-formats";

// Official SBOM validation schemas.
import cyclonedxSchema from "../schemas/bom-1.6.schema.json";
import spdxSchema from "../schemas/spdx.schema.json";
import jsfSchema from "../schemas/jsf-0.82.schema.json";

// Loads environment variables from the .env file.
import "dotenv/config";


// ============================================================
// 2. APPLICATION AND VALIDATION SETUP
// ============================================================

// Create the AJV validator.
const ajv = new Ajv({
 allErrors: true,
 strict: false,
});

// Add additional format validation support.
addFormats(ajv);

// Register the supported SBOM schemas.
ajv.addSchema(spdxSchema);
ajv.addSchema(jsfSchema);

// Compile the CycloneDX schema validator.
const validateSbom = ajv.compile(cyclonedxSchema);

// Create the Express application.
const app = express();

// Parse incoming JSON and preserve the original request body.
// The raw body is needed for webhook signature verification.
app.use(express.json({
 verify: (req, _res, buf) => {
 (req as express.Request & { rawBody?: Buffer }).rawBody =
 Buffer.from(buf);
 },
}));

// Configure the server port.
const PORT = 3000;

// Minimum age required for a package version.
const PACKAGE_AGE_COOLDOWN_DAYS = 7;


// ============================================================
// 3. DATA STRUCTURES AND SCAN HISTORY
// ============================================================

// Defines the information stored for each completed scan.
interface ScanHistoryEntry {
 scanId: string;
 status: string;
 dependencyCount: number;
 createdAt: string;
 policyFindings: string[];
}

// Stores scan history in memory.
const scanHistory: ScanHistoryEntry[] = [];


// Defines the information stored for an asynchronous scan.
interface ScanJob {
 scanId: string;
 status: "QUEUED" | "RUNNING" | "COMPLETED" | "FAILED";
 createdAt: string;
 result?: unknown;
 error?: string;
}

// Stores asynchronous scan jobs.
const scanJobs = new Map<string, ScanJob>();


// ============================================================
// 4. ACCOUNT PLANS AND SCAN QUOTAS
// ============================================================

// Defines the account subscription information.
interface AccountPlan {
 plan: "free" | "pro";
 scansUsed: number;
 month: string;
 expiresAt: number | null;
}

// Stores account plans in memory.
const accountPlans = new Map<string, AccountPlan>();

// Monthly scan limits for each subscription plan.
const FREE_SCAN_LIMIT = 30;
const PRO_SCAN_LIMIT = 1000;

// Pro subscriptions last 30 days in this demonstration.
const PRO_DURATION_DAYS = 30;


// Checks whether an account is allowed to perform another scan.
function checkScanQuota(accountId: string) {
 const currentMonth = new Date().toISOString().slice(0, 7);

 let account = accountPlans.get(accountId);

 // Create a Free account if the account does not exist.
 if (!account) {
 account = {
 plan: "free",
 scansUsed: 0,
 month: currentMonth,
 expiresAt: null,
 };
 }

 // Reset scan usage when a new month begins.
 if (account.month !== currentMonth) {
 account.scansUsed = 0;
 account.month = currentMonth;
 }

 // Downgrade expired Pro accounts to Free.
 if (
 account.plan === "pro" &&
 account.expiresAt !== null &&
 Date.now() > account.expiresAt
 ) {
 account.plan = "free";
 account.expiresAt = null;
 }

 // Select the scan limit for the current plan.
 const limit =
 account.plan === "pro" ? PRO_SCAN_LIMIT : FREE_SCAN_LIMIT;

 // Reject scans when the monthly limit has been reached.
 if (account.scansUsed >= limit) {
 accountPlans.set(accountId, account);

 return {
 allowed: false,
 plan: account.plan,
 scansUsed: account.scansUsed,
 limit,
 };
 }

 accountPlans.set(accountId, account);

 return {
 allowed: true,
 plan: account.plan,
 scansUsed: account.scansUsed,
 limit,
 };
}


// ============================================================
// 5. CONCURRENT PROCESSING HELPER
// ============================================================

// Processes multiple items concurrently without exceeding
// the specified number of workers.
async function mapWithConcurrency<T, R>(
 items: T[],
 limit: number,
 worker: (item: T, index: number) => Promise<R>
): Promise<R[]> {

 const results: R[] = new Array(items.length);
 let nextIndex = 0;

 // Each worker processes the next available item.
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

 // Never create more workers than available items.
 const workerCount = Math.min(limit, items.length);

 await Promise.all(
 Array.from({ length: workerCount }, () => runWorker())
 );

 return results;
}


// ============================================================
// 6. SECURITY POLICY CONFIGURATION
// ============================================================

// Defines an approved package and version.
interface AllowListEntry {
 name: string;
 version: string;
 reason: string;
 expiresAt: string;
}

// Defines the security rules used during dependency scanning.
interface SecurityPolicy {
 blockCritical: boolean;
 blockHigh: boolean;
 minimumPackageAgeDays: number;
 allowList: AllowListEntry[];
}

// Default security policy for DepGuard.
const defaultPolicy: SecurityPolicy = {
 blockCritical: true,
 blockHigh: true,
 minimumPackageAgeDays: 7,

 // Packages approved for the allow-list demonstration.
 allowList: [
 {
 name: "@hapi/pez",
 version: "6.1.3",
 reason: "Approved for the DepGuard allow-list demonstration.",
 expiresAt: "2026-12-05T23:59:59.000Z",
 },
 ],
};


// ============================================================
// 7. OSV AND NPM CACHES
// ============================================================

// Cache for package vulnerability scan results.
const osvCache = new Map<
 string,
 {
 expiresAt: number;
 result: unknown;
 }
>();

// Cache for individual OSV advisory information.
const osvAdvisoryCache = new Map<
 string,
 {
 expiresAt: number;
 result: unknown;
 }
>();

// Cache duration: 24 hours.
const OSV_CACHE_TTL = 24 * 60 * 60 * 1000;

// Cache for npm package publication metadata.
const npmMetadataCache = new Map<
 string,
 {
 expiresAt: number;
 time: Record<string, string>;
 }
>();


// ============================================================
// 8. OSV ADVISORY LOOKUP
// ============================================================

// Retrieves full vulnerability information for a specific
// advisory ID, using the cache when available.
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

 // Store the advisory for 24 hours.
 osvAdvisoryCache.set(advisoryId, {
 expiresAt: Date.now() + OSV_CACHE_TTL,
 result: advisory,
 });

 return advisory;
}


// ============================================================
// 9. NPM PACKAGE PUBLICATION DATE LOOKUP
// ============================================================

// Retrieves the publication date of a particular package version.
// Uses cached npm metadata to reduce repeated requests.
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


// ============================================================
// 10. OSV BATCH VULNERABILITY SCANNING
// ============================================================

// Checks multiple dependencies against OSV.
// Cached results are reused, while missing results are requested
// together through the OSV batch endpoint.
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

 // Identify packages that do not have valid cached results.
 const missingDependencies = dependencies.filter(
 (dependency, index) => results[index] === null
 );

 if (missingDependencies.length > 0) {
 console.log(
 `OSV FRESH REQUEST: ${missingDependencies.length} packages`
 );

 // Send one batch request for the missing dependencies.
 const response = await fetch(
 "https://api.osv.dev/v1/querybatch",
 {
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
 }
 );

 if (!response.ok) {
 throw new Error(
 `OSV.dev request failed: ${response.status}`
 );
 }

 const freshResults = await response.json() as {
 results?: unknown[];
 };

 const freshItems = freshResults.results ?? [];

 // Cache each result and place it in its original position.
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


// ============================================================
// 11. SECURITY POLICY EVALUATION
// ============================================================

// Evaluates dependency warnings and vulnerabilities against
// the configured security policy.
// Returns PASS, FAIL or ERROR with the corresponding findings.
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

 // Check whether this exact package version is approved.
 const allowed = policy.allowList.some(
 (entry) =>
 entry.name === packageName &&
 entry.version === packageVersion &&
 entry.reason.trim() !== "" &&
 new Date(entry.expiresAt).getTime() > Date.now()
 );

 // Skip policy findings for approved package versions.
 if (allowed) {
 continue;
 }

 // Report errors when package age cannot be verified.
 if (
 policy.minimumPackageAgeDays > 0 &&
 dependency.ageCheckError
 ) {
 status = "ERROR";

 findings.push(
 `${packageName}: package age could not be verified.`
 );
 }

 // Flag package versions that are too recently published.
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

 // Check for missing integrity information.
 if (dependency.warnings.includes("Missing integrity field")) {
 if (status !== "ERROR") status = "FAIL";

 findings.push(
 `${packageName}: missing integrity field.`
 );
 }

 // Check for installation scripts.
 if (dependency.warnings.includes("Package has an install script")) {
 if (status !== "ERROR") status = "FAIL";

 findings.push(
 `${packageName}: has an install script.`
 );
 }

 // Check for packages using non-npm registry sources.
 if (
 dependency.warnings.includes(
 "Package uses a non-npm registry source"
 )
 ) {
 if (status !== "ERROR") status = "FAIL";

 findings.push(
 `${packageName}: uses a non-npm registry source.`
 );
 }

 // Evaluate each vulnerability associated with the dependency.
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
 // Retrieve the complete OSV advisory.
 const fullAdvisory = await getOsvAdvisory(vuln.id);

 const advisory = fullAdvisory as {
 database_specific?: { severity?: string };
 severity?: { type?: string; score?: string }[];
 id?: string;
 };

 const severity = (
 advisory.database_specific?.severity ?? ""
 ).toUpperCase();

 // Block critical and high-severity vulnerabilities
 // according to the active policy.
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


// ============================================================
// 12. LOCKFILE VERSION VALIDATION
// ============================================================

// Checks whether the supplied lockfile is a valid JSON object
// and whether its npm lockfile version is supported.
function validateLockfileVersion(data: unknown): {
 valid: boolean;
 message: string;
} {

 if (
 typeof data !== "object" ||
 data === null ||
 Array.isArray(data)
 ) {
 return {
 valid: false,
 message: "Lockfile must be a JSON object.",
 };
 }

 const lockfile = data as Record<string, unknown>;

 // Only npm lockfile versions 2 and 3 are supported.
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


// ============================================================
// 13. ADDITIONAL JSON MIDDLEWARE
// ============================================================

// Parses JSON request bodies with a maximum size of 10 MB.
// This second JSON middleware is preserved from your original code.
app.use(express.json({ limit: "10mb" }));


// ============================================================
// 14. BASIC API ROUTES
// ============================================================

// Root route: confirms that DepGuard is running.
app.get("/", (_req, res) => {
 res.json({
 message: "welcome to depguard",
 status: "running",
 });
});

// Test route: returns the JSON data received by the API.
app.post("/test", (req, res) => {
 res.json({
 message: "DepGuard received your data!",
 receivedData: req.body,
 });
});


// ============================================================
// 15. LOCKFILE VALIDATION ROUTE
// ============================================================

// POST /validate-lockfile
// Checks whether the submitted npm lockfile version is supported.
app.post("/validate-lockfile", (req, res) => {
 const result = validateLockfileVersion(req.body);

 if (!result.valid) {
 return res.status(400).json(result);
 }

 return res.status(200).json(result);
});


// ============================================================
// 16. MAIN DEPENDENCY SCANNING ROUTE
// ============================================================

// POST /scan-lockfile
// Scans an npm lockfile for vulnerable and risky dependencies.
// Also checks package age, applies security policies,
// generates a CycloneDX SBOM and records scan history.
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

 // Identify the account making the scan request.
 const accountId = req.header("x-account-id");

 if (!accountId) {
 return res.status(400).json({
 error: "Missing x-account-id header.",
 });
 }

 // Check whether the account has remaining monthly scans.
 const quota = checkScanQuota(accountId);

 if (!quota.allowed) {
 return res.status(402).json({
 error: "Monthly scan quota exceeded.",
 plan: quota.plan,
 scansUsed: quota.scansUsed,
 limit: quota.limit,
 });
 }

 // Collect package information without installing or running anything.
 const dependencyEntries = Object.entries(packages).filter(
 ([path]) =>
 typeof path === "string" &&
 path.startsWith("node_modules/")
 );

 // Process dependencies with a maximum of five concurrent workers.
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

 // Identify packages that do not use the npm registry.
 const isNonRegistrySource =
 resolved !== null &&
 !(
 resolved.startsWith("https://registry.npmjs.org/") ||
 resolved.startsWith("http://registry.npmjs.org/")
 );

 const warnings: string[] = [];

 // Check whether the package has integrity information.
 if (
 typeof packageInfo.integrity !== "string" ||
 packageInfo.integrity.trim() === ""
 ) {
 warnings.push("Missing integrity field");
 }

 // Check whether the package has an installation script.
 if (packageInfo.hasInstallScript === true) {
 warnings.push("Package has an install script");
 }

 // Check whether the package uses a non-npm registry source.
 if (isNonRegistrySource) {
 warnings.push("Package uses a non-npm registry source");
 }

 let publishedAt: string | null = null;
 let packageAgeDays: number | null = null;
 let ageCheckError: string | null = null;

 // Retrieve the publication date for the package version.
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

 // Flag versions published within the cooldown period.
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


 // --------------------------------------------------------
 // 16A. CHECK DEPENDENCIES AGAINST OSV
 // --------------------------------------------------------

 // Keep only dependencies that have valid package versions.
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

 // Retrieve vulnerability information from OSV.
 const osvResults = await checkOsvVulnerabilities(osvDependencies);

 const osvResultItems = (
 osvResults as {
 results?: Array<{ vulns?: unknown[] }>;
 }
 ).results ?? [];

 // Associate OSV vulnerability results with their packages.
 const osvResultsByPackage = new Map<string, unknown[]>();

 osvDependencies.forEach((dependency, index) => {
 const key = `${dependency.name}@${dependency.version}`;

 const vulnerabilities = osvResultItems[index]?.vulns ?? [];

 osvResultsByPackage.set(key, vulnerabilities);
 });

 // Attach vulnerability information to each dependency.
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


 // --------------------------------------------------------
 // 16B. GENERATE CYCLONEDX SBOM COMPONENTS
 // --------------------------------------------------------

 // Convert scanned dependencies into CycloneDX components.
 const sbomComponents = dependencies.map((dependency) => {

 const integrity =
 typeof dependency.integrity === "string"
 ? dependency.integrity
 : "";

 // Convert SHA-512 integrity information into an SBOM hash.
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


 // --------------------------------------------------------
 // 16C. APPLY SECURITY POLICY
 // --------------------------------------------------------

 // Evaluate all dependencies against the default security policy.
 const policyResult = await evaluatePolicy(
 dependenciesWithVulnerabilities,
 defaultPolicy
 );


 // --------------------------------------------------------
 // 16D. GENERATE AND VALIDATE SBOM
 // --------------------------------------------------------

 // Build the CycloneDX 1.6 SBOM document.
 const sbom = {
 bomFormat: "CycloneDX",
 specVersion: "1.6",
 serialNumber: `urn:uuid:${randomUUID()}`,
 version: 1,
 components: sbomComponents,
 };

 // Validate the generated SBOM against the CycloneDX schema.
 const isSbomValid = validateSbom(sbom);

 const sbomValidationErrors = validateSbom.errors ?? [];


 // --------------------------------------------------------
 // 16E. RECORD SCAN HISTORY AND UPDATE QUOTA
 // --------------------------------------------------------

 // Create a record of the completed scan.
 const scanRecord: ScanHistoryEntry = {
 scanId: randomUUID(),
 status: policyResult.status,
 dependencyCount: dependencies.length,
 createdAt: new Date().toISOString(),
 policyFindings: policyResult.findings,
 };

 // Add the scan to the scan history.
 scanHistory.push(scanRecord);

 // Increase the account's monthly scan usage.
 const account = accountPlans.get(accountId);

 if (account) {
 account.scansUsed += 1;
 accountPlans.set(accountId, account);
 }


 // --------------------------------------------------------
 // 16F. RETURN SCAN RESULTS
 // --------------------------------------------------------

 return res.status(200).json({
 message: "Lockfile scanned successfully.",
 status: policyResult.status,
 policyFindings: policyResult.findings,
 dependencyCount: dependencies.length,
 sbomComponents,
 sbom,
 sbomValid: isSbomValid,
 sbomValidationErrors,
 dependencies: dependenciesWithVulnerabilities,
 osvResults,
 });
});


// ============================================================
// 17. PRO PLAN UPGRADE DEMONSTRATION
// ============================================================

// POST /demo-upgrade
// Simulates upgrading an account to the Pro plan.
// This is a local demonstration and does not process a real payment.
app.post("/demo-upgrade", (req, res) => {

 const accountId = req.header("x-account-id");

 if (!accountId) {
 return res.status(400).json({
 error: "Missing x-account-id header.",
 });
 }

 const currentMonth = new Date().toISOString().slice(0, 7);

 // Create the simulated Pro subscription.
 const account: AccountPlan = {
 plan: "pro",
 scansUsed: 0,
 month: currentMonth,
 expiresAt: Date.now() + PRO_DURATION_DAYS * 24 * 60 * 60 * 1000,
 };

 accountPlans.set(accountId, account);

 return res.status(200).json({
 message: "Demo Pro upgrade activated.",
 plan: account.plan,
 scanLimit: PRO_SCAN_LIMIT,
 expiresAt: new Date(account.expiresAt!).toISOString(),
 paymentStatus: "SIMULATED_NOT_PAID",
 });
});


// ============================================================
// 18. SCAN HISTORY ROUTE
// ============================================================

// GET /scan-history
// Returns the total number of scans and their recorded details.
app.get("/scan-history", (_req, res) => {
 return res.status(200).json({
 totalScans: scanHistory.length,
 scans: scanHistory,
 });
});


// ============================================================
// 19. ASYNCHRONOUS SCANNING ROUTE
// ============================================================

// POST /scan-async
// Accepts a scan request immediately and processes it in the background.
app.post("/scan-async", (req, res) => {

 const scanId = randomUUID();

 // Create a new asynchronous scan job.
 const scanJob: ScanJob = {
 scanId,
 status: "QUEUED",
 createdAt: new Date().toISOString(),
 };

 scanJobs.set(scanId, scanJob);

 const lockfile = req.body;

 // Return the scan ID immediately without waiting for the scan.
 res.status(202).json({
 message: "Scan accepted and queued.",
 scanId,
 status: scanJob.status,
 });

 // Start processing the scan after the response is sent.
 setImmediate(async () => {

 const job = scanJobs.get(scanId);

 if (!job) return;

 job.status = "RUNNING";

 try {
 // Send the lockfile to the main scanning endpoint.
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
 error instanceof Error
 ? error.message
 : "Scan failed.";
 }
 });
});


// ============================================================
// 20. ASYNCHRONOUS SCAN STATUS ROUTE
// ============================================================

// GET /scan-status/:scanId
// Returns the current status of a background scan.
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


// ============================================================
// 21. ASYNCHRONOUS SCAN RESULTS ROUTE
// ============================================================

// GET /scan-results/:scanId
// Returns the results of a background scan once completed.
app.get("/scan-results/:scanId", (req, res) => {

 const { scanId } = req.params;

 const job = scanJobs.get(scanId);

 if (!job) {
 return res.status(404).json({
 error: "Scan not found.",
 });
 }

 // Inform the client if the scan is still running.
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


// ============================================================
// 22. LOCKFILE COMPARISON ROUTE
// ============================================================

// POST /scan-diff
// Compares two lockfiles and identifies added, removed
// and changed dependencies.
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

 // Identify newly added packages and packages with changed versions.
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

 // Identify packages that were removed.
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


// ============================================================
// 23. GLOBAL ERROR HANDLING
// ============================================================

// Handles errors that occur while processing API requests.
// Returns appropriate responses for oversized requests,
// invalid JSON and unexpected server errors.
app.use((
 err: any,
 req: express.Request,
 res: express.Response,
 next: express.NextFunction
) => {

 // Reject request bodies larger than the configured limit.
 if (err.type === "entity.too.large") {
 return res.status(413).json({
 error: "Request body is too large. Maximum allowed size is 10 MB.",
 });
 }

 // Reject malformed JSON requests.
 if (err instanceof SyntaxError && "body" in err) {
 return res.status(400).json({
 error: "Invalid JSON request body.",
 });
 }

 // Log unexpected errors on the server.
 console.error(err);

 return res.status(500).json({
 error: "An unexpected server error occurred.",
 });
});


// ============================================================
// 24. WEBHOOK REPLAY PROTECTION
// ============================================================

// Stores transaction references that have already been processed.
// Prevents the same transaction from being recorded more than once.
const demoProcessedTransactions = new Set<string>();

// Stores payments accepted by the local webhook demonstration.
const demoWebhookPayments: Array<{
 transaction_ref: string;
 amount: number;
 status: string;
}> = [];


// ============================================================
// 25. WEBHOOK SIGNATURE VERIFICATION
// ============================================================

// POST /demo-webhook
// Verifies the HMAC signature of an incoming simulated payment webhook.
// Rejects invalid signatures and ignores previously processed
// transaction references to prevent replay attacks.
app.post("/demo-webhook", (req, res) => {

 const signature = req.header("x-demo-signature");

 // Retrieve the original, unmodified request body.
 const rawBody = (
 req as express.Request & { rawBody?: Buffer }
 ).rawBody;

 // Retrieve the local webhook secret from the environment.
 const secret = process.env.WEBHOOK_DEMO_SECRET;

 if (!signature || !rawBody || !secret) {
 return res.status(400).json({
 error: "Missing signature, request body, or secret.",
 });
 }

 // Generate the expected HMAC-SHA256 signature.
 const expectedSignature = createHmac("sha256", secret)
 .update(rawBody)
 .digest("hex");

 const received = Buffer.from(signature, "hex");
 const expected = Buffer.from(expectedSignature, "hex");

 // Compare signatures safely to reject invalid or tampered requests.
 if (
 received.length !== expected.length ||
 !timingSafeEqual(received, expected)
 ) {
 return res.status(401).json({
 error: "Invalid webhook signature. Request rejected.",
 });
 }

 // Extract payment information from the verified request.
 const { transaction_ref, amount, status } = req.body;

 if (!transaction_ref || !amount || !status) {
 return res.status(400).json({
 error: "Invalid payment notification.",
 });
 }

 // Check whether this transaction has already been processed.
 if (demoProcessedTransactions.has(transaction_ref)) {
 return res.status(200).json({
 message: "Duplicate webhook ignored.",
 processed: false,
 });
 }

 // Mark the transaction as processed.
 demoProcessedTransactions.add(transaction_ref);

 // Record the payment once.
 demoWebhookPayments.push({
 transaction_ref,
 amount,
 status,
 });

 return res.status(200).json({
 message: "Webhook processed successfully.",
 processed: true,
 totalPaymentsRecorded: demoWebhookPayments.length,
 });
});


// ============================================================
// 26. START THE SERVER
// ============================================================

// Start DepGuard and listen for incoming requests.
app.listen(PORT, () => {
 console.log(`DepGuard is running on port ${PORT}`);
});