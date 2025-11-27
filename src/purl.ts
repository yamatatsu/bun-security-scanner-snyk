/**
 * Copyright (c) 2025 Tatsuya Yamamoto. All rights reserved.
 * SPDX-License-Identifier: MIT
 */

/**
 * Package URL (PURL) utilities
 * Converts npm package names and versions to PURL format for Snyk API
 *
 * PURL format: pkg:npm/package-name@version
 * Scoped packages: pkg:npm/%40scope%2Fpackage-name@version
 */

import type { PURL } from "./schema.js";

/**
 * Convert an npm package name and version to PURL format
 *
 * @param name - Package name (e.g., "express" or "@types/node")
 * @param version - Package version (e.g., "4.17.1")
 * @returns PURL string (e.g., "pkg:npm/express@4.17.1" or "pkg:npm/%40types%2Fnode@18.0.0")
 *
 * @example
 * ```typescript
 * toPURL("express", "4.17.1")
 * // => "pkg:npm/express@4.17.1"
 *
 * toPURL("@types/node", "18.0.0")
 * // => "pkg:npm/%40types%2Fnode@18.0.0"
 * ```
 */
export function toPURL(name: string, version: string): PURL {
	// Encode scoped package names
	// @scope/package → %40scope%2Fpackage
	let encodedName = name;

	if (name.startsWith("@")) {
		// Replace @ with %40 and / with %2F
		encodedName = name.replace(/^@/, "%40").replace(/\//, "%2F");
	}

	return `pkg:npm/${encodedName}@${version}`;
}

/**
 * Parse a PURL back to package name and version
 *
 * @param purl - PURL string
 * @returns Object with name and version, or null if invalid
 *
 * @example
 * ```typescript
 * fromPURL("pkg:npm/express@4.17.1")
 * // => { name: "express", version: "4.17.1" }
 *
 * fromPURL("pkg:npm/%40types%2Fnode@18.0.0")
 * // => { name: "@types/node", version: "18.0.0" }
 * ```
 */
export function fromPURL(
	purl: string,
): { name: string; version: string } | null {
	// Match pattern: pkg:npm/name@version
	const match = purl.match(/^pkg:npm\/([^@]+)@(.+)$/);

	if (!match || !match[1] || !match[2]) {
		return null;
	}

	let name = match[1];
	const version = match[2];

	// Decode scoped package names
	// %40scope%2Fpackage → @scope/package
	if (name.startsWith("%40")) {
		name = name.replace(/^%40/, "@").replace(/%2F/, "/");
	}

	return { name, version };
}

/**
 * Validate if a string is a valid PURL
 *
 * @param purl - String to validate
 * @returns true if valid PURL format
 */
export function isValidPURL(purl: string): purl is PURL {
	return /^pkg:npm\/[^@]+@.+$/.test(purl);
}

/**
 * Convert multiple packages to PURLs
 *
 * @param packages - Array of Bun.Security.Package objects
 * @returns Array of PURL strings
 */
export function packagesToPURLs(packages: Bun.Security.Package[]): PURL[] {
	return packages.map((pkg) => toPURL(pkg.name, pkg.version));
}
