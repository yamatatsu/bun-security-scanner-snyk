/**
 * Copyright (c) 2025 Tatsuya Yamamoto. All rights reserved.
 * SPDX-License-Identifier: MIT
 */

import { describe, expect, test } from "bun:test";
import { toPURL, fromPURL, isValidPURL, packagesToPURLs } from "../src/purl.js";

describe("PURL Conversion", () => {
	describe("toPURL", () => {
		test("converts regular package to PURL", () => {
			const purl = toPURL("express", "4.17.1");
			expect(purl).toBe("pkg:npm/express@4.17.1");
		});

		test("converts scoped package to PURL with encoding", () => {
			const purl = toPURL("@types/node", "18.0.0");
			expect(purl).toBe("pkg:npm/%40types%2Fnode@18.0.0");
		});

		test("converts scoped package with org to PURL", () => {
			const purl = toPURL("@babel/core", "7.20.0");
			expect(purl).toBe("pkg:npm/%40babel%2Fcore@7.20.0");
		});

		test("handles package with hyphens", () => {
			const purl = toPURL("event-stream", "3.3.6");
			expect(purl).toBe("pkg:npm/event-stream@3.3.6");
		});

		test("handles pre-release versions", () => {
			const purl = toPURL("typescript", "5.0.0-beta.1");
			expect(purl).toBe("pkg:npm/typescript@5.0.0-beta.1");
		});

		test("handles version with build metadata", () => {
			const purl = toPURL("package", "1.0.0+build.123");
			expect(purl).toBe("pkg:npm/package@1.0.0+build.123");
		});
	});

	describe("fromPURL", () => {
		test("parses regular PURL to package info", () => {
			const result = fromPURL("pkg:npm/express@4.17.1");
			expect(result).toEqual({
				name: "express",
				version: "4.17.1",
			});
		});

		test("parses scoped PURL to package info", () => {
			const result = fromPURL("pkg:npm/%40types%2Fnode@18.0.0");
			expect(result).toEqual({
				name: "@types/node",
				version: "18.0.0",
			});
		});

		test("parses PURL with pre-release version", () => {
			const result = fromPURL("pkg:npm/typescript@5.0.0-beta.1");
			expect(result).toEqual({
				name: "typescript",
				version: "5.0.0-beta.1",
			});
		});

		test("returns null for invalid PURL", () => {
			const result = fromPURL("invalid-purl");
			expect(result).toBeNull();
		});

		test("returns null for wrong ecosystem", () => {
			const result = fromPURL("pkg:pypi/requests@2.28.0");
			expect(result).toBeNull();
		});

		test("returns null for missing version", () => {
			const result = fromPURL("pkg:npm/express");
			expect(result).toBeNull();
		});
	});

	describe("isValidPURL", () => {
		test("validates correct PURL", () => {
			expect(isValidPURL("pkg:npm/express@4.17.1")).toBe(true);
		});

		test("validates scoped PURL", () => {
			expect(isValidPURL("pkg:npm/%40types%2Fnode@18.0.0")).toBe(true);
		});

		test("rejects invalid format", () => {
			expect(isValidPURL("invalid")).toBe(false);
		});

		test("rejects missing version", () => {
			expect(isValidPURL("pkg:npm/express")).toBe(false);
		});

		test("rejects wrong ecosystem", () => {
			expect(isValidPURL("pkg:pypi/requests@2.28.0")).toBe(false);
		});
	});

	describe("packagesToPURLs", () => {
		test("converts multiple packages to PURLs", () => {
			const packages: Bun.Security.Package[] = [
				{
					name: "express",
					version: "4.17.1",
					requestedRange: "^4.0.0",
					tarball: "https://registry.npmjs.org/express/-/express-4.17.1.tgz",
				},
				{
					name: "@types/node",
					version: "18.0.0",
					requestedRange: "^18.0.0",
					tarball: "https://registry.npmjs.org/@types/node/-/node-18.0.0.tgz",
				},
				{
					name: "lodash",
					version: "4.17.21",
					requestedRange: "^4.0.0",
					tarball: "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
				},
			];

			const purls = packagesToPURLs(packages);

			expect(purls).toEqual([
				"pkg:npm/express@4.17.1",
				"pkg:npm/%40types%2Fnode@18.0.0",
				"pkg:npm/lodash@4.17.21",
			]);
		});

		test("handles empty package array", () => {
			const purls = packagesToPURLs([]);
			expect(purls).toEqual([]);
		});

		test("handles single package", () => {
			const packages: Bun.Security.Package[] = [
				{
					name: "express",
					version: "4.17.1",
					requestedRange: "^4.0.0",
					tarball: "https://registry.npmjs.org/express/-/express-4.17.1.tgz",
				},
			];

			const purls = packagesToPURLs(packages);
			expect(purls).toEqual(["pkg:npm/express@4.17.1"]);
		});
	});

	describe("Round-trip conversion", () => {
		test("converts to PURL and back for regular package", () => {
			const name = "express";
			const version = "4.17.1";

			const purl = toPURL(name, version);
			const result = fromPURL(purl);

			expect(result).toEqual({ name, version });
		});

		test("converts to PURL and back for scoped package", () => {
			const name = "@types/node";
			const version = "18.0.0";

			const purl = toPURL(name, version);
			const result = fromPURL(purl);

			expect(result).toEqual({ name, version });
		});

		test("converts to PURL and back for complex version", () => {
			const name = "typescript";
			const version = "5.0.0-beta.1+build.123";

			const purl = toPURL(name, version);
			const result = fromPURL(purl);

			expect(result).toEqual({ name, version });
		});
	});
});
