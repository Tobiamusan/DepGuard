import express from "express"; 
const app = express();

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
const osvCache = new Map<
string,
{
expiresAt: number;
result: unknown;
}
>();

const OSV_CACHE_TTL = 24 * 60 * 60 * 1000;

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

return res.status(200).json({
 message: "Lockfile scanned successfully.",
 dependencyCount: dependencies.length,
 dependencies: dependenciesWithVulnerabilities,
 osvResults,
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