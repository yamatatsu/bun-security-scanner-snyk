/**
 * Copyright (c) 2025 maloma7 (Original OSV implementation)
 * Copyright (c) 2025 Tatsuya Yamamoto (Snyk migration)
 * SPDX-License-Identifier: MIT
 */

import type {
	SnykVulnerability,
	SnykIssuesRequest,
	SnykIssuesResponse,
	PURL,
} from "./schema.js";
import { SnykIssuesResponseSchema, SnykErrorSchema } from "./schema.js";
import { SNYK_API, HTTP, ENV, getConfig } from "./constants.js";
import { withRetry } from "./retry.js";
import { logger } from "./logger.js";
import { packagesToPURLs } from "./purl.js";

/**
 * Error thrown when Snyk API returns 403 Forbidden
 * This indicates insufficient permissions or plan limitations
 */
export class SnykPermissionError extends Error {
	constructor(message: string) {
		super(message);
		this.name = "SnykPermissionError";
	}
}

/**
 * Snyk API Client
 * Handles all communication with Snyk REST API including batch queries
 */
export class SnykClient {
	private readonly baseUrl: string;
	private readonly orgId: string;
	private readonly apiToken: string;
	private readonly timeout: number;
	private readonly apiVersion: string;

	constructor() {
		this.baseUrl = getConfig(ENV.API_BASE_URL, SNYK_API.BASE_URL);
		this.timeout = getConfig(ENV.TIMEOUT_MS, SNYK_API.TIMEOUT_MS);
		this.apiVersion = SNYK_API.API_VERSION;

		// Get required credentials from environment
		const orgId = Bun.env[ENV.ORG_ID];
		const apiToken = Bun.env[ENV.API_TOKEN];

		if (!orgId || !apiToken) {
			throw new Error("SNYK_ORG_ID and SNYK_API_TOKEN must be set");
		}

		this.orgId = orgId;
		this.apiToken = apiToken;
	}

	/**
	 * Query vulnerabilities for multiple packages
	 * Uses Snyk REST API with PURL format
	 */
	async queryVulnerabilities(
		packages: Bun.Security.Package[],
	): Promise<SnykVulnerability[]> {
		if (packages.length === 0) {
			return [];
		}

		// Deduplicate packages by name@version
		const uniquePackages = this.deduplicatePackages(packages);
		logger.info(
			`Scanning ${uniquePackages.length} unique packages (${packages.length} total)`,
		);

		// Convert packages to PURLs
		const purls = packagesToPURLs(uniquePackages);

		// Create package map for later reference
		const packageMap = this.createPackageMap(uniquePackages);

		// Query Snyk API in batches
		const allIssues = await this.queryInBatches(purls);

		// Convert Snyk issues to our internal vulnerability format
		const vulnerabilities = this.convertIssuesToVulnerabilities(
			allIssues,
			packageMap,
		);

		logger.info(`Found ${vulnerabilities.length} vulnerabilities`);
		return vulnerabilities;
	}

	/**
	 * Deduplicate packages by name@version to avoid redundant queries
	 */
	private deduplicatePackages(
		packages: Bun.Security.Package[],
	): Bun.Security.Package[] {
		const packageMap = new Map<string, Bun.Security.Package>();

		for (const pkg of packages) {
			const key = `${pkg.name}@${pkg.version}`;
			if (!packageMap.has(key)) {
				packageMap.set(key, pkg);
			}
		}

		const uniquePackages = Array.from(packageMap.values());

		if (uniquePackages.length < packages.length) {
			logger.debug(
				`Deduplicated ${packages.length} packages to ${uniquePackages.length} unique packages`,
			);
		}

		return uniquePackages;
	}

	/**
	 * Create a map of package name@version to package for quick lookup
	 */
	private createPackageMap(
		packages: Bun.Security.Package[],
	): Map<string, Bun.Security.Package> {
		const map = new Map<string, Bun.Security.Package>();
		for (const pkg of packages) {
			map.set(`${pkg.name}@${pkg.version}`, pkg);
		}
		return map;
	}

	/**
	 * Query Snyk API in batches
	 */
	private async queryInBatches(
		purls: PURL[],
	): Promise<SnykIssuesResponse["data"]> {
		const allIssues: SnykIssuesResponse["data"] = [];

		// Process PURLs in batches
		for (let i = 0; i < purls.length; i += SNYK_API.MAX_BATCH_SIZE) {
			const batchPurls = purls.slice(i, i + SNYK_API.MAX_BATCH_SIZE);

			try {
				const issues = await this.executeBatchQuery(batchPurls);
				allIssues.push(...issues);
			} catch (error) {
				// Re-throw permission errors immediately - these should stop installation
				if (error instanceof SnykPermissionError) {
					throw error;
				}

				// Log and continue for other errors (network issues, etc.)
				logger.error(`Batch query failed for ${batchPurls.length} packages`, {
					error: error instanceof Error ? error.message : String(error),
					startIndex: i,
				});
				// Continue with next batch rather than failing completely
			}
		}

		return allIssues;
	}

	/**
	 * Execute a single batch query to Snyk API
	 */
	private async executeBatchQuery(
		purls: PURL[],
	): Promise<SnykIssuesResponse["data"]> {
		logger.debug(`Querying Snyk API for ${purls.length} packages`);

		// Construct request body
		const requestBody: SnykIssuesRequest = {
			data: {
				attributes: {
					purls,
				},
				type: "resource",
			},
		};

		const url = `${this.baseUrl}/orgs/${this.orgId}/packages/issues?version=${this.apiVersion}`;

		const response = await withRetry(async () => {
			const res = await fetch(url, {
				method: "POST",
				headers: {
					"Content-Type": HTTP.CONTENT_TYPE,
					Authorization: `token ${this.apiToken}`,
				},
				body: JSON.stringify(requestBody),
				signal: AbortSignal.timeout(this.timeout),
			});

			// Handle different status codes
			if (res.status === 403) {
				// Permission denied - likely due to plan limitations
				let errorMessage =
					"Organization is not allowed to perform this action.";
				let errorCode = "SNYK-OSSI-1040";

				try {
					const errorData = await res.json();
					const parsedError = SnykErrorSchema.safeParse(errorData);
					if (parsedError.success && parsedError.data.errors.length > 0) {
						const firstError = parsedError.data.errors[0];
						if (firstError) {
							errorMessage = firstError.detail || errorMessage;
							errorCode = firstError.code || errorCode;
						}
					}
				} catch {
					// Use default error message
				}

				throw new SnykPermissionError(errorMessage);
			}

			if (res.status === 429) {
				// Rate limit exceeded
				const retryAfter = res.headers.get("Retry-After");
				const message = retryAfter
					? `Rate limit exceeded. Retry after ${retryAfter} seconds.`
					: "Rate limit exceeded.";
				throw new Error(message);
			}

			if (!res.ok) {
				// Try to parse error response
				let errorMessage = `Snyk API returned ${res.status}: ${res.statusText}`;
				try {
					const errorData = await res.json();
					const parsedError = SnykErrorSchema.safeParse(errorData);
					if (parsedError.success && parsedError.data.errors.length > 0) {
						errorMessage = parsedError.data.errors
							.map((e) => e.detail)
							.join(", ");
					}
				} catch {
					// Use default error message
				}
				throw new Error(errorMessage);
			}

			return res;
		}, `Snyk batch query (${purls.length} packages)`);

		const data = await response.json();
		const parsed = SnykIssuesResponseSchema.parse(data);

		logger.debug(
			`Batch query returned ${parsed.data.length} issues for ${purls.length} packages`,
		);

		return parsed.data;
	}

	/**
	 * Convert Snyk issues to internal vulnerability format
	 */
	private convertIssuesToVulnerabilities(
		issues: SnykIssuesResponse["data"],
		_packageMap: Map<string, Bun.Security.Package>,
	): SnykVulnerability[] {
		const vulnerabilities: SnykVulnerability[] = [];

		for (const issue of issues) {
			const attrs = issue.attributes;

			// Extract severity
			const severity = attrs.effectiveSeverityLevel || attrs.severity;

			// Extract URL from references
			let url: string | undefined;
			if (attrs.references && attrs.references.length > 0) {
				url = attrs.references[0]?.url;
			}

			// Extract description
			const description = attrs.description || attrs.title;

			// Create vulnerability object
			const vulnerability: SnykVulnerability = {
				id: issue.id,
				title: attrs.title,
				description,
				severity,
				cvssScore: attrs.cvssScore,
				url,
			};

			vulnerabilities.push(vulnerability);
		}

		return vulnerabilities;
	}
}
