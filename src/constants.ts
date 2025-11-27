/**
 * Copyright (c) 2025 maloma7 (Original OSV implementation)
 * Copyright (c) 2025 Tatsuya Yamamoto (Snyk migration)
 * SPDX-License-Identifier: MIT
 */

/**
 * Centralized configuration constants for Snyk Scanner
 * All magic numbers and configuration values consolidated here
 */

import type { FatalSeverity } from "./types.js";

/**
 * Snyk API Configuration
 */
export const SNYK_API = {
	/** Base URL for Snyk REST API */
	BASE_URL: "https://api.snyk.io/rest",

	/** API version to use */
	API_VERSION: "2024-10-15",

	/** Request timeout in milliseconds */
	TIMEOUT_MS: 30_000,

	/** Maximum packages per batch query (to be determined by testing) */
	MAX_BATCH_SIZE: 100,

	/** Maximum retry attempts for failed requests */
	MAX_RETRY_ATTEMPTS: 2,

	/** Delay between retry attempts in milliseconds */
	RETRY_DELAY_MS: 1_000,

	/** Rate limit: 180 requests per minute per user */
	RATE_LIMIT_PER_MINUTE: 180,
} as const;

/**
 * HTTP Configuration
 */
export const HTTP = {
	/** Content type for Snyk API requests (JSON:API format) */
	CONTENT_TYPE: "application/vnd.api+json",

	/** User agent for requests */
	USER_AGENT: "bun-snyk-scanner/1.0.0",
} as const;

/**
 * Security Configuration
 */
export const SECURITY = {
	/** CVSS score threshold for fatal advisories */
	CVSS_FATAL_THRESHOLD: 7.0,

	/** Database severities that map to fatal level */
	FATAL_SEVERITIES: [
		"CRITICAL",
		"HIGH",
	] as const satisfies readonly FatalSeverity[],

	/** Maximum vulnerabilities to process per package */
	MAX_VULNERABILITIES_PER_PACKAGE: 100,

	/** Maximum length for vulnerability descriptions */
	MAX_DESCRIPTION_LENGTH: 200,
} as const;

/**
 * Performance Configuration
 */
export const PERFORMANCE = {
	/** Enable batch queries for better performance */
	USE_BATCH_QUERIES: true,

	/** Maximum concurrent vulnerability detail requests */
	MAX_CONCURRENT_DETAILS: 10,

	/** Maximum response size in bytes (32MB) */
	MAX_RESPONSE_SIZE: 32 * 1024 * 1024,
} as const;

/**
 * Environment variable configuration
 */
export const ENV = {
	/** Log level environment variable */
	LOG_LEVEL: "SNYK_LOG_LEVEL",

	/** Snyk API Token (required) */
	API_TOKEN: "SNYK_API_TOKEN",

	/** Snyk Organization ID (required) */
	ORG_ID: "SNYK_ORG_ID",

	/** Custom API base URL override */
	API_BASE_URL: "SNYK_API_BASE_URL",

	/** Custom timeout override */
	TIMEOUT_MS: "SNYK_TIMEOUT_MS",

	/** Disable batch queries */
	DISABLE_BATCH: "SNYK_DISABLE_BATCH",
} as const;

/**
 * Get configuration value with environment variable override
 */
export function getConfig<T>(
	envVar: string,
	defaultValue: T,
	parser?: (value: string) => T,
): T {
	const envValue = Bun.env[envVar];
	if (!envValue) return defaultValue;

	if (parser) {
		try {
			return parser(envValue);
		} catch {
			return defaultValue;
		}
	}

	// Type-safe parsing for common types
	if (typeof defaultValue === "number") {
		const parsed = Number(envValue);
		return (Number.isNaN(parsed) ? defaultValue : parsed) as T;
	}

	if (typeof defaultValue === "boolean") {
		return (envValue.toLowerCase() === "true") as T;
	}

	return envValue as T;
}
