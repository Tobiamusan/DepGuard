DepGuard – Dependency Supply-Chain Security Gate
A Node.js and TypeScript security tool designed to identify vulnerabilities and potential supply-chain risks in npm dependencies.

Table of Contents
Overview
Features
Technology Stack
Installation
Environment Variables
Running the Application
API Endpoints
Testing
Current Development Status
Security Notice

Overview
DepGuard is a dependency security scanning tool that helps developers identify security risks in their npm projects before deployment.

It analyses package-lock.json files, extracts installed dependencies, checks packages against the OSV.dev vulnerability database, and identifies potential supply-chain security risks.

The project aims to make dependency security more accessible by helping developers identify vulnerable and potentially risky third-party packages.

Features
1. Lockfile Validation
Accepts npm package-lock.json files.
Validates lockfile structure.
Checks supported lockfile formats.
2. Dependency Extraction
Extracts dependencies from npm lockfiles.
Identifies package names and versions.
Retrieves resolved package URLs.
Extracts package integrity hashes.
Preserves individual package versions.
3. Vulnerability Scanning
Integrates with the OSV.dev vulnerability database.
Uses the OSV batch query API.
Checks npm packages against known security advisories.
Associates vulnerability results with individual dependencies.
4. Supply-Chain Risk Detection
DepGuard identifies several potential dependency risks:

Packages containing installation scripts.
Packages with missing integrity hashes.
Packages using non-npm registry sources.
Recently published package versions.
5. Package Age Verification
Retrieves package publication dates from the npm registry.
Calculates package age in days.
Flags package versions younger than the configured seven-day cooldown.
Caches npm metadata for 24 hours.
6. Performance Optimisation
Limits concurrent package metadata checks to five.
Implements a 24-hour in-memory cache for OSV vulnerability results.
Reuses cached vulnerability information during repeated scans.

Technology StackTechnologyPurposeNode.jsJavaScript runtimeTypeScriptBackend programming languageExpress.jsAPI frameworkOSV.devVulnerability databasenpm RegistryPackage metadataGitVersion controlInstallationPrerequisitesEnsure the following tools are installed:Node.jsnpmGitClone the Repositorygit clone YOUR_GITHUB_REPOSITORY_URLNavigate to the Project Directorycd depguardInstall Dependenciesnpm installEnvironment VariablesCreate a .env file in the project root when environment variables are required.Use .env.example as a reference for the required variable names.Never commit private credentials, API secrets, or actual environment values to GitHub.Running the ApplicationStart the development server:npm run devThe application runs on:http://localhost:3000API EndpointsMethodEndpointDescriptionPOST/validate-lockfileValidates an npm lockfilePOST/scan-lockfileScans dependencies for vulnerabilities and security risksAPI TestingThe endpoints can be tested using Postman or Thunder Client.Submit a package-lock.json file to the appropriate endpoint and inspect the returned JSON response.The scan response includes dependency information, package age information, risk warnings, and OSV vulnerability results.External ServicesDepGuard currently uses the following external services:OSV.dev API: https://api.osv.dev/v1/querybatchnpm Registry: https://registry.npmjs.org/These services provide vulnerability information and package publication metadata used during dependency analysis.Current Development StatusDepGuard is actively under development.The following features are planned or still being implemented:Security policy engine with PASS, FAIL, and ERROR decisions.Critical and high vulnerability blocking.Package and version allow-listing with expiry dates and reasons.CycloneDX SBOM generation.Scan history and project management.Asynchronous scanning and scan comparison.CI integration and automated security checks.Free and Pro subscription management.Squad payment integration and webhook verification.npm provenance and signature verification.GitHub Actions workflow security checks.Dependency maintainer-change detection.Security NoticeDepGuard is currently under development. Its existing scanning capabilities do not guarantee that a package or application is completely secure.Vulnerability and package metadata checks depend on external services and their availability.The current in-memory caches are cleared when the application process restarts.Project InformationProject Name: DepGuardProject Category: Backend Development / Software Supply-Chain SecurityProgramming Language: TypeScriptProject Status: In Development
