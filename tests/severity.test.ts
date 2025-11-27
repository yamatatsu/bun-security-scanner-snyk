/**
 * Copyright (c) 2025 maloma7 (Original OSV implementation)
 * Copyright (c) 2025 Tatsuya Yamamoto (Snyk migration)
 * SPDX-License-Identifier: MIT
 */

import { beforeEach, describe, expect, test } from "bun:test";
import { mapSeverityToLevel, getSeverityDescription } from "../src/severity.js";
import type { SnykVulnerability } from "../src/schema.js";

describe("Snyk Severity Assessment", () => {
	beforeEach(() => {
		// Set log level to error to reduce test output
		process.env.SNYK_LOG_LEVEL = "error";
	});

	describe("Snyk Severity Level Mapping", () => {
		test("maps critical severity to fatal", () => {
			const vuln: SnykVulnerability = {
				id: "SNYK-JS-LODASH-001",
				severity: "critical",
			};

			const level = mapSeverityToLevel(vuln);
			expect(level).toBe("fatal");
		});

		test("maps high severity to fatal", () => {
			const vuln: SnykVulnerability = {
				id: "SNYK-JS-LODASH-002",
				severity: "high",
			};

			const level = mapSeverityToLevel(vuln);
			expect(level).toBe("fatal");
		});

		test("maps medium severity to warn", () => {
			const vuln: SnykVulnerability = {
				id: "SNYK-JS-LODASH-003",
				severity: "medium",
			};

			const level = mapSeverityToLevel(vuln);
			expect(level).toBe("warn");
		});

		test("maps low severity to warn", () => {
			const vuln: SnykVulnerability = {
				id: "SNYK-JS-LODASH-004",
				severity: "low",
			};

			const level = mapSeverityToLevel(vuln);
			expect(level).toBe("warn");
		});
	});

	describe("CVSS Score Priority", () => {
		test("CVSS score takes priority over severity level", () => {
			const vuln: SnykVulnerability = {
				id: "SNYK-JS-TEST-001",
				severity: "low",
				cvssScore: 9.8,
			};

			const level = mapSeverityToLevel(vuln);
			expect(level).toBe("fatal");
		});

		test("CVSS 7.0 (threshold) maps to fatal", () => {
			const vuln: SnykVulnerability = {
				id: "SNYK-JS-TEST-002",
				cvssScore: 7.0,
			};

			const level = mapSeverityToLevel(vuln);
			expect(level).toBe("fatal");
		});

		test("CVSS 6.9 (below threshold) maps to warn", () => {
			const vuln: SnykVulnerability = {
				id: "SNYK-JS-TEST-003",
				cvssScore: 6.9,
			};

			const level = mapSeverityToLevel(vuln);
			expect(level).toBe("warn");
		});

		test("CVSS 10.0 (maximum) maps to fatal", () => {
			const vuln: SnykVulnerability = {
				id: "SNYK-JS-TEST-004",
				cvssScore: 10.0,
			};

			const level = mapSeverityToLevel(vuln);
			expect(level).toBe("fatal");
		});

		test("CVSS 0.0 (minimum) maps to warn", () => {
			const vuln: SnykVulnerability = {
				id: "SNYK-JS-TEST-005",
				cvssScore: 0.0,
			};

			const level = mapSeverityToLevel(vuln);
			expect(level).toBe("warn");
		});

		test("invalid CVSS score (negative) falls through to severity", () => {
			const vuln: SnykVulnerability = {
				id: "SNYK-JS-TEST-006",
				cvssScore: -1.0,
				severity: "high",
			};

			const level = mapSeverityToLevel(vuln);
			expect(level).toBe("fatal"); // Uses severity instead
		});

		test("invalid CVSS score (>10) falls through to severity", () => {
			const vuln: SnykVulnerability = {
				id: "SNYK-JS-TEST-007",
				cvssScore: 11.0,
				severity: "low",
			};

			const level = mapSeverityToLevel(vuln);
			expect(level).toBe("warn"); // Uses severity instead
		});
	});

	describe("Edge Cases", () => {
		test("missing all severity information defaults to warn", () => {
			const vuln: SnykVulnerability = {
				id: "SNYK-JS-TEST-008",
			};

			const level = mapSeverityToLevel(vuln);
			expect(level).toBe("warn");
		});

		test("undefined severity defaults to warn", () => {
			const vuln: SnykVulnerability = {
				id: "SNYK-JS-TEST-009",
				severity: undefined,
			};

			const level = mapSeverityToLevel(vuln);
			expect(level).toBe("warn");
		});

		test("undefined cvssScore falls back to severity", () => {
			const vuln: SnykVulnerability = {
				id: "SNYK-JS-TEST-010",
				cvssScore: undefined,
				severity: "critical",
			};

			const level = mapSeverityToLevel(vuln);
			expect(level).toBe("fatal");
		});
	});

	describe("Real-World Scenarios", () => {
		test("classifies RCE vulnerability as fatal", () => {
			const vuln: SnykVulnerability = {
				id: "SNYK-JS-LODASH-590103",
				title: "Prototype Pollution",
				severity: "critical",
				cvssScore: 9.8,
			};

			const level = mapSeverityToLevel(vuln);
			expect(level).toBe("fatal");
		});

		test("classifies DoS vulnerability based on severity", () => {
			const vuln: SnykVulnerability = {
				id: "SNYK-JS-EXPRESS-12345",
				title: "Denial of Service",
				severity: "medium",
				cvssScore: 5.3,
			};

			const level = mapSeverityToLevel(vuln);
			expect(level).toBe("warn");
		});

		test("classifies information disclosure vulnerability", () => {
			const vuln: SnykVulnerability = {
				id: "SNYK-JS-AXIOS-67890",
				title: "Information Exposure",
				severity: "low",
				cvssScore: 3.7,
			};

			const level = mapSeverityToLevel(vuln);
			expect(level).toBe("warn");
		});
	});

	describe("Boundary Testing", () => {
		test("CVSS 6.99 is warn", () => {
			const vuln: SnykVulnerability = {
				id: "SNYK-JS-TEST-011",
				cvssScore: 6.99,
			};

			expect(mapSeverityToLevel(vuln)).toBe("warn");
		});

		test("CVSS 7.01 is fatal", () => {
			const vuln: SnykVulnerability = {
				id: "SNYK-JS-TEST-012",
				cvssScore: 7.01,
			};

			expect(mapSeverityToLevel(vuln)).toBe("fatal");
		});
	});

	describe("getSeverityDescription", () => {
		test("formats CVSS score when available", () => {
			const vuln: SnykVulnerability = {
				id: "SNYK-JS-TEST-013",
				cvssScore: 8.5,
			};

			const description = getSeverityDescription(vuln);
			expect(description).toBe("CVSS 8.5");
		});

		test("returns uppercase severity when no CVSS", () => {
			const vuln: SnykVulnerability = {
				id: "SNYK-JS-TEST-014",
				severity: "high",
			};

			const description = getSeverityDescription(vuln);
			expect(description).toBe("HIGH");
		});

		test("returns UNKNOWN when no severity info", () => {
			const vuln: SnykVulnerability = {
				id: "SNYK-JS-TEST-015",
			};

			const description = getSeverityDescription(vuln);
			expect(description).toBe("UNKNOWN");
		});

		test("prioritizes CVSS over severity level", () => {
			const vuln: SnykVulnerability = {
				id: "SNYK-JS-TEST-016",
				cvssScore: 7.5,
				severity: "critical",
			};

			const description = getSeverityDescription(vuln);
			expect(description).toBe("CVSS 7.5");
		});

		test("formats CVSS with one decimal place", () => {
			const vuln: SnykVulnerability = {
				id: "SNYK-JS-TEST-017",
				cvssScore: 9.0,
			};

			const description = getSeverityDescription(vuln);
			expect(description).toBe("CVSS 9.0");
		});
	});
});
