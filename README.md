# DepGuard — Dependency Security Scanner

DepGuard is a backend dependency security scanning API built with Node.js, Express and TypeScript.

It helps developers identify vulnerable and risky npm dependencies, enforce security policies, compare lockfiles, generate and validate Software Bill of Materials (SBOMs), and integrate security checks into CI pipelines.

## Features

- Lockfile validation (npm lockfile versions 2 and 3).
- Vulnerability detection using the OSV database.
- Detection of risky installation scripts.
- Detection of recently published packages.
- Detection of missing integrity information and non-registry sources.
- Security policies for critical and high-severity vulnerabilities.
- Package allow-listing with reasons and expiry dates.
- CycloneDX SBOM generation and validation.
- Asynchronous dependency scanning.
- Scan history and scan results.
- Lockfile comparison and dependency change detection.
- CI integration with PASS/FAIL exit codes.
- Free and Pro scan quota demonstrations.
- Webhook signature verification and replay protection.

## Technology Stack

- Node.js
- Express.js
- TypeScript
- OSV vulnerability database
- CycloneDX
- AJV schema validation
- npm lockfiles

## Installation

Clone the repository:

```bash
git clone https://github.com/Tobiamusan/DepGuard.git



## Postman API Documentation

View the complete DepGuard API documentation, including endpoints and request examples:

https://documenter.getpostman.com/view/57167646/2sBYHYtd7X
