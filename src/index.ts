/**
 * Copyright (c) 2025 maloma7 (Original OSV implementation)
 * Copyright (c) 2025 Tatsuya Yamamoto (Snyk migration)
 * SPDX-License-Identifier: MIT
 */

/// <reference types="bun-types" />
import "./types.js";
import { SnykClient, SnykPermissionError } from "./client.js";
import { VulnerabilityProcessor } from "./processor.js";
import { logger } from "./logger.js";

/**
 * Validate required environment variables for Snyk API
 * Throws an error if credentials are not configured
 */
function validateEnvironmentVariables(): void {
	const token = Bun.env.SNYK_API_TOKEN;
	const orgId = Bun.env.SNYK_ORG_ID;

	if (!token || !orgId) {
		const missingVars: string[] = [];
		if (!token) missingVars.push("SNYK_API_TOKEN");
		if (!orgId) missingVars.push("SNYK_ORG_ID");

		throw new Error(
			`Snyk API credentials not configured

This scanner requires a Snyk Enterprise plan.

Missing environment variables: ${missingVars.join(", ")}

Don't have an Enterprise plan?
Use the free alternative: npm i -D @bun-security-scanner/osv
Learn more: https://www.npmjs.com/package/@bun-security-scanner/osv

If you have an Enterprise plan, set these environment variables:
export SNYK_API_TOKEN="your-token"
export SNYK_ORG_ID="your-org-id"

Get credentials:
- API Token: https://docs.snyk.io/snyk-api/authentication-for-api
- Organization ID: https://app.snyk.io/manage/settings`,
		);
	}
}

/**
 * Bun Security Scanner for Snyk vulnerability detection
 * Integrates with Snyk API to detect vulnerabilities in npm packages
 * Protects against supply chain attacks like Shai-Hulud worms
 */
export const scanner: Bun.Security.Scanner = {
	version: "1", // This is the version of Bun security scanner implementation. You should keep this set as '1'

	async scan({ packages }) {
		try {
			// Validate environment variables at scan time
			validateEnvironmentVariables();

			logger.info(`Starting Snyk scan for ${packages.length} packages`);

			// Initialize components
			const client = new SnykClient();
			const processor = new VulnerabilityProcessor();

			// Fetch vulnerabilities from Snyk API
			const vulnerabilities = await client.queryVulnerabilities(packages);

			// Process vulnerabilities into security advisories
			const advisories = processor.processVulnerabilities(
				vulnerabilities,
				packages,
			);

			logger.info(
				`Snyk scan completed: ${advisories.length} advisories found for ${packages.length} packages`,
			);

			return advisories;
		} catch (error) {
			// Handle permission errors - these should stop installation
			if (error instanceof SnykPermissionError) {
				const errorMessage = `Snyk API permission denied

This scanner requires a Snyk Enterprise plan.
Your current plan does not have access to the required API endpoint.

Error: ${error.message}

Don't have an Enterprise plan?
Switch to the free alternative:

  bun remove bun-security-scanner-snyk
  bun add -D @bun-security-scanner/osv

Update your bunfig.toml:
  [install.security]
  scanner = "@bun-security-scanner/osv"

Learn more: https://www.npmjs.com/package/@bun-security-scanner/osv`;

				logger.error("Snyk API permission denied", {
					error: error.message,
				});

				// Re-throw to stop installation
				throw new Error(errorMessage);
			}

			// For other errors (network issues, etc.), log and continue
			const message = error instanceof Error ? error.message : String(error);
			logger.error("Snyk scanner encountered an unexpected error", {
				error: message,
			});

			// Fail-safe: allow installation to proceed on scanner errors
			return [];
		}
	},
};

// CLI entry point
if (import.meta.main) {
	const { runCli } = await import("./cli.js");
	await runCli();
}
