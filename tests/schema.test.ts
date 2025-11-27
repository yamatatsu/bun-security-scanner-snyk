/**
 * Copyright (c) 2025 maloma7 (Original OSV implementation)
 * Copyright (c) 2025 Tatsuya Yamamoto (Snyk migration)
 * SPDX-License-Identifier: MIT
 */

import { describe, expect, test } from "bun:test";
import {
	PURLSchema,
	SnykSeveritySchema,
	SnykIssuesRequestSchema,
	SnykIssuesResponseSchema,
	SnykErrorSchema,
} from "../src/schema.js";

describe("Snyk Schema Validation", () => {
	describe("PURLSchema", () => {
		test("validates standard PURL", () => {
			const purl = "pkg:npm/lodash@4.17.21";
			const result = PURLSchema.safeParse(purl);
			expect(result.success).toBe(true);
		});

		test("validates scoped package PURL", () => {
			const purl = "pkg:npm/%40types%2Fnode@18.0.0";
			const result = PURLSchema.safeParse(purl);
			expect(result.success).toBe(true);
		});

		test("rejects invalid PURL", () => {
			const purl = "not-a-purl";
			const result = PURLSchema.safeParse(purl);
			expect(result.success).toBe(false);
		});
	});

	describe("SnykSeveritySchema", () => {
		test("validates critical severity", () => {
			const result = SnykSeveritySchema.safeParse("critical");
			expect(result.success).toBe(true);
		});

		test("validates high severity", () => {
			const result = SnykSeveritySchema.safeParse("high");
			expect(result.success).toBe(true);
		});

		test("validates medium severity", () => {
			const result = SnykSeveritySchema.safeParse("medium");
			expect(result.success).toBe(true);
		});

		test("validates low severity", () => {
			const result = SnykSeveritySchema.safeParse("low");
			expect(result.success).toBe(true);
		});

		test("rejects invalid severity", () => {
			const result = SnykSeveritySchema.safeParse("invalid");
			expect(result.success).toBe(false);
		});
	});

	describe("SnykIssuesRequestSchema", () => {
		test("validates request with single PURL", () => {
			const request = {
				data: {
					attributes: {
						purls: ["pkg:npm/lodash@4.17.20"],
					},
					type: "resource",
				},
			};

			const result = SnykIssuesRequestSchema.safeParse(request);
			expect(result.success).toBe(true);
		});

		test("validates request with multiple PURLs", () => {
			const request = {
				data: {
					attributes: {
						purls: [
							"pkg:npm/lodash@4.17.20",
							"pkg:npm/express@4.18.0",
							"pkg:npm/%40types%2Fnode@18.0.0",
						],
					},
					type: "resource",
				},
			};

			const result = SnykIssuesRequestSchema.safeParse(request);
			expect(result.success).toBe(true);
		});

		test("rejects missing purls", () => {
			const request = {
				data: {
					attributes: {},
					type: "resource",
				},
			};

			const result = SnykIssuesRequestSchema.safeParse(request);
			expect(result.success).toBe(false);
		});
	});

	describe("SnykIssuesResponseSchema", () => {
		test("validates empty response", () => {
			const response = {
				data: [],
				jsonapi: {
					version: "1.0",
				},
				links: {
					self: "/rest/orgs/test/packages/issues",
				},
			};

			const result = SnykIssuesResponseSchema.safeParse(response);
			expect(result.success).toBe(true);
		});

		test("validates response with issues", () => {
			const response = {
				data: [
					{
						id: "SNYK-JS-LODASH-12345",
						type: "issue",
						attributes: {
							title: "Prototype Pollution",
							description: "Lodash is vulnerable to Prototype Pollution",
							severity: "high",
							cvss_score: 7.5,
							url: "https://security.snyk.io/vuln/SNYK-JS-LODASH-12345",
							package_name: "lodash",
							package_version: "4.17.20",
						},
					},
				],
				jsonapi: {
					version: "1.0",
				},
				links: {
					self: "/rest/orgs/test/packages/issues",
				},
			};

			const result = SnykIssuesResponseSchema.safeParse(response);
			expect(result.success).toBe(true);
		});

		test("validates response with multiple issues", () => {
			const response = {
				data: [
					{
						id: "SNYK-1",
						type: "issue",
						attributes: {
							title: "Vulnerability 1",
							severity: "critical",
						},
					},
					{
						id: "SNYK-2",
						type: "issue",
						attributes: {
							title: "Vulnerability 2",
							severity: "medium",
						},
					},
				],
				jsonapi: {
					version: "1.0",
				},
				links: {
					self: "/rest/orgs/test/packages/issues",
				},
			};

			const result = SnykIssuesResponseSchema.safeParse(response);
			expect(result.success).toBe(true);
		});
	});

	describe("SnykErrorSchema", () => {
		test("validates error response", () => {
			const error = {
				jsonapi: {
					version: "1.0",
				},
				errors: [
					{
						id: "error-id",
						status: "403",
						code: "SNYK-OSSI-1040",
						title: "Forbidden",
						detail: "Organization is not allowed to perform this action.",
					},
				],
			};

			const result = SnykErrorSchema.safeParse(error);
			expect(result.success).toBe(true);
		});

		test("validates error with minimal fields", () => {
			const error = {
				jsonapi: {
					version: "1.0",
				},
				errors: [
					{
						detail: "Bad request details",
						status: "400",
					},
				],
			};

			const result = SnykErrorSchema.safeParse(error);
			expect(result.success).toBe(true);
		});

		test("validates multiple errors", () => {
			const error = {
				jsonapi: {
					version: "1.0",
				},
				errors: [
					{
						detail: "Error 1 details",
						status: "400",
					},
					{
						detail: "Error 2 details",
						status: "400",
					},
				],
			};

			const result = SnykErrorSchema.safeParse(error);
			expect(result.success).toBe(true);
		});

		test("rejects missing errors array", () => {
			const error = {
				jsonapi: {
					version: "1.0",
				},
			};

			const result = SnykErrorSchema.safeParse(error);
			expect(result.success).toBe(false);
		});
	});
});
