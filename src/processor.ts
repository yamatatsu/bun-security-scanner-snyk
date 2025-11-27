/**
 * Copyright (c) 2025 maloma7. All rights reserved.
 * SPDX-License-Identifier: MIT
 */

import type { SnykVulnerability } from "./schema.js";
import { mapSeverityToLevel } from "./severity.js";
import { logger } from "./logger.js";

/**
 * Process Snyk vulnerabilities into Bun security advisories
 * Handles vulnerability-to-package matching and advisory generation
 */
export class VulnerabilityProcessor {
	/**
	 * Convert Snyk vulnerabilities to Bun security advisories
	 */
	processVulnerabilities(
		vulnerabilities: SnykVulnerability[],
		packages: Bun.Security.Package[],
	): Bun.Security.Advisory[] {
		if (vulnerabilities.length === 0 || packages.length === 0) {
			return [];
		}

		logger.info(
			`Processing ${vulnerabilities.length} vulnerabilities against ${packages.length} packages`,
		);

		const advisories: Bun.Security.Advisory[] = [];

		// Create a package map for quick lookup
		const packageMap = new Map<string, Bun.Security.Package>();
		for (const pkg of packages) {
			packageMap.set(`${pkg.name}@${pkg.version}`, pkg);
		}

		// Process each vulnerability
		for (const vuln of vulnerabilities) {
			// Try to match vulnerability to a package
			const matchedPackage = this.findMatchingPackage(vuln, packageMap);

			if (matchedPackage) {
				const advisory = this.createAdvisory(vuln, matchedPackage);
				advisories.push(advisory);

				logger.debug(
					`Created advisory for ${matchedPackage.name}@${matchedPackage.version}`,
					{
						vulnerability: vuln.id,
						level: advisory.level,
					},
				);
			}
		}

		logger.info(`Generated ${advisories.length} security advisories`);
		return advisories;
	}

	/**
	 * Find the package that matches this vulnerability
	 * Uses package name and version from vulnerability data
	 */
	private findMatchingPackage(
		vuln: SnykVulnerability,
		packageMap: Map<string, Bun.Security.Package>,
	): Bun.Security.Package | null {
		// If vulnerability has package info, use it for matching
		if (vuln.packageName && vuln.packageVersion) {
			const key = `${vuln.packageName}@${vuln.packageVersion}`;
			return packageMap.get(key) || null;
		}

		// Fallback: return first package (this shouldn't happen with Snyk API)
		// as each vulnerability should be associated with a specific package
		return packageMap.values().next().value || null;
	}

	/**
	 * Create a Bun security advisory from a Snyk vulnerability
	 */
	private createAdvisory(
		vuln: SnykVulnerability,
		pkg: Bun.Security.Package,
	): Bun.Security.Advisory {
		const level = mapSeverityToLevel(vuln);
		const message = vuln.title || vuln.id;
		const url = vuln.url || null;
		const description = this.getVulnerabilityDescription(vuln);

		return {
			id: vuln.id,
			message,
			level,
			package: pkg.name,
			url,
			description,
		};
	}

	/**
	 * Get a descriptive summary of the vulnerability
	 */
	private getVulnerabilityDescription(vuln: SnykVulnerability): string | null {
		if (vuln.description?.trim()) {
			const desc = vuln.description.trim();

			// Truncate if too long
			if (desc.length > 200) {
				// Try to get first sentence
				const firstSentence = desc.match(/^[^.!?]*[.!?]/)?.[0];
				if (firstSentence && firstSentence.length <= 200) {
					return firstSentence;
				}
				// Truncate to 200 chars
				return `${desc.substring(0, 197)}...`;
			}

			return desc;
		}

		// Fallback to title
		if (vuln.title?.trim()) {
			return vuln.title.trim();
		}

		return null;
	}
}
