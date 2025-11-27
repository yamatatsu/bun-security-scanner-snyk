/**
 * Copyright (c) 2025 maloma7 (Original OSV implementation)
 * Copyright (c) 2025 Tatsuya Yamamoto (Snyk migration)
 * SPDX-License-Identifier: MIT
 */

import { z } from "zod";

/**
 * Snyk API Request Schemas
 */

// PURL (Package URL) format: pkg:npm/package-name@version
export const PURLSchema = z.string().startsWith("pkg:npm/");

// Request body for POST /orgs/{org_id}/packages/issues
export const SnykIssuesRequestSchema = z.object({
	data: z.object({
		attributes: z.object({
			purls: z.array(PURLSchema),
		}),
		type: z.literal("resource"),
	}),
});

/**
 * Snyk API Response Schemas
 */

// JSON:API top-level structure
export const JSONAPIVersionSchema = z.object({
	version: z.string(),
});

// Snyk severity levels
export const SnykSeveritySchema = z.enum(["critical", "high", "medium", "low"]);

// Issue attributes from Snyk API
export const SnykIssueAttributesSchema = z
	.object({
		// Core identifiers
		key: z.string().optional(), // Unique issue key
		title: z.string().optional(), // Vulnerability title
		type: z.string().optional(), // Issue type (e.g., "package_vulnerability")

		// Severity information
		severity: SnykSeveritySchema.optional(),
		effectiveSeverityLevel: SnykSeveritySchema.optional(),

		// CVSS scores
		cvssScore: z.number().optional(),

		// Description
		description: z.string().optional(),

		// References
		references: z
			.array(
				z.object({
					title: z.string().optional(),
					url: z.string(),
				}),
			)
			.optional(),

		// Package information
		problems: z
			.array(
				z.object({
					id: z.string(),
					source: z.string().optional(),
					type: z.string().optional(),
					url: z.string().optional(),
					// Additional problem details
				}),
			)
			.optional(),

		// Additional fields (Snyk API may return more)
		// Using catchall for forward compatibility
	})
	.passthrough();

// Individual issue in the response
export const SnykIssueSchema = z.object({
	id: z.string(), // Issue ID (e.g., "SNYK-JS-LODASH-590103")
	type: z.literal("issue"),
	attributes: SnykIssueAttributesSchema,
});

// Complete response from POST /orgs/{org_id}/packages/issues
export const SnykIssuesResponseSchema = z.object({
	jsonapi: JSONAPIVersionSchema,
	data: z.array(SnykIssueSchema),
	// Meta information about packages
	meta: z
		.object({
			packages: z
				.array(
					z
						.object({
							purl: PURLSchema,
							// Additional package metadata
						})
						.passthrough(),
				)
				.optional(),
		})
		.passthrough()
		.optional(),
});

/**
 * Error response schema
 */
export const SnykErrorSchema = z.object({
	jsonapi: JSONAPIVersionSchema.optional(),
	errors: z.array(
		z.object({
			status: z.string(),
			detail: z.string(),
			title: z.string().optional(),
			code: z.string().optional(),
		}),
	),
});

/**
 * Exported types
 */
export type PURL = z.infer<typeof PURLSchema>;
export type SnykIssuesRequest = z.infer<typeof SnykIssuesRequestSchema>;
export type SnykSeverity = z.infer<typeof SnykSeveritySchema>;
export type SnykIssueAttributes = z.infer<typeof SnykIssueAttributesSchema>;
export type SnykIssue = z.infer<typeof SnykIssueSchema>;
export type SnykIssuesResponse = z.infer<typeof SnykIssuesResponseSchema>;
export type SnykError = z.infer<typeof SnykErrorSchema>;

/**
 * Internal vulnerability type (normalized from Snyk response)
 * This matches the structure expected by VulnerabilityProcessor
 */
export interface SnykVulnerability {
	id: string;
	title?: string;
	description?: string;
	severity?: SnykSeverity;
	cvssScore?: number;
	url?: string;
	packageName?: string;
	packageVersion?: string;
}
