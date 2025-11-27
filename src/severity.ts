/**
 * Copyright (c) 2025 maloma7. All rights reserved.
 * SPDX-License-Identifier: MIT
 */

import type { SnykVulnerability, SnykSeverity } from "./schema.js";
import { SECURITY } from "./constants.js";

/**
 * Map Snyk severity to Bun advisory level
 * Uses CVSS scores and Snyk severity levels to determine if vulnerability is fatal or warning
 *
 * @param vuln - Snyk vulnerability object
 * @returns "fatal" for critical/high severity, "warn" for medium/low
 */
export function mapSeverityToLevel(vuln: SnykVulnerability): "fatal" | "warn" {
	// Priority 1: Check CVSS score if available
	if (vuln.cvssScore !== undefined) {
		if (
			vuln.cvssScore >= SECURITY.CVSS_FATAL_THRESHOLD &&
			vuln.cvssScore <= 10.0
		) {
			return "fatal";
		}
		// Invalid CVSS scores (outside 0-10 range) fall through to next check
		if (vuln.cvssScore >= 0 && vuln.cvssScore < SECURITY.CVSS_FATAL_THRESHOLD) {
			return "warn";
		}
	}

	// Priority 2: Check Snyk severity level
	if (vuln.severity) {
		return isFatalSeverity(vuln.severity) ? "fatal" : "warn";
	}

	// Default: warn if no severity information available
	return "warn";
}

/**
 * Check if Snyk severity level is fatal (critical or high)
 */
function isFatalSeverity(severity: SnykSeverity): boolean {
	return severity === "critical" || severity === "high";
}

/**
 * Get a human-readable severity description
 */
export function getSeverityDescription(vuln: SnykVulnerability): string {
	if (vuln.cvssScore !== undefined) {
		return `CVSS ${vuln.cvssScore.toFixed(1)}`;
	}
	if (vuln.severity) {
		return vuln.severity.toUpperCase();
	}
	return "UNKNOWN";
}
