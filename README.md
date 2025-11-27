<!--
Copyright (c) 2025 maloma7 (Original OSV implementation)
Copyright (c) 2025 Tatsuya Yamamoto (Snyk migration)
SPDX-License-Identifier: MIT
-->

# Bun Security Scanner with Snyk

A production-grade security scanner for [Bun](https://bun.sh/) that integrates with [Snyk](https://snyk.io/) to detect known vulnerabilities in npm packages during installation. Specifically designed to protect against supply chain attacks like the Shai-Hulud worm.

[![License: MIT](https://img.shields.io/badge/License-MIT-471694)](LICENSE)
[![Built with Claude](https://img.shields.io/badge/Built_with-Claude-471694?style=flat&logo=claude&logoColor=471694)](https://anthropic.com/claude-code)
[![Checked with Biome](https://img.shields.io/badge/Checked_with-Biome-471694?style=flat&logo=biome&logoColor=471694)](https://biomejs.dev)
[![Secured with Lefthook](https://img.shields.io/badge/Secured_with-Lefthook-471694?style=flat&logo=lefthook&logoColor=471694)](https://lefthook.dev/)

## ⚠️ Requirements

**This scanner requires a Snyk Enterprise plan.**

- Snyk API Token with appropriate permissions
- Snyk Organization ID
- Active Snyk **Enterprise** subscription

> **Note:** The Snyk REST API endpoint used by this scanner (`POST /rest/orgs/{org_id}/packages/issues`) is only available on Snyk Enterprise plans.
>
> **Don't have an Enterprise plan?**
> Use [@bun-security-scanner/osv](https://www.npmjs.com/package/@bun-security-scanner/osv) instead - it's free and works for everyone!

## What is Snyk?

[Snyk](https://snyk.io/) is a developer security platform that helps find and fix vulnerabilities in open source dependencies, container images, and infrastructure as code. This scanner integrates with Snyk's REST API to provide:

- **Comprehensive Vulnerability Database**: Curated vulnerability data from multiple sources
- **Accurate Package Intelligence**: Detailed vulnerability information for npm packages
- **Real-time Protection**: Latest security advisories and patches
- **Enterprise-Grade Security**: Trusted by thousands of organizations worldwide

## Why Snyk Scanner?

### Protection Against Supply Chain Attacks

The primary goal of this scanner is to **protect against self-replicating malware** like the Shai-Hulud worm, which:

- Steals npm tokens and GitHub Personal Access Tokens
- Self-replicates by publishing infected versions of packages
- Executes malicious code via preinstall/postinstall scripts
- Spreads through both direct and transitive dependencies

**This scanner checks ALL packages (including transitive dependencies) BEFORE any install scripts execute.**

## Features

- **Real-time Scanning**: Checks packages against Snyk API during installation
- **Supply Chain Protection**: Scans both direct and transitive dependencies
- **High Performance**: Efficient batch queries with smart deduplication
- **Fail-safe**: Never blocks installations due to scanner errors
- **Structured Logging**: Configurable logging levels with contextual information
- **Precise Matching**: Accurate vulnerability-to-package version matching
- **Rate Limit Handling**: Automatic retry with exponential backoff
- **Configurable**: Environment variable configuration for all settings

## Installation

### Prerequisites

1. **Create a Snyk account**: [https://snyk.io/signup](https://snyk.io/signup)
2. **Get your API token**: [https://docs.snyk.io/snyk-api/authentication-for-api](https://docs.snyk.io/snyk-api/authentication-for-api)
3. **Find your Organization ID**: [https://docs.snyk.io/snyk-admin/manage-groups-and-organizations/organizations/organization-general-settings](https://docs.snyk.io/snyk-admin/manage-groups-and-organizations/organizations/organization-general-settings)

### Install the Scanner

```bash
# Install as a dev dependency
bun add -d bun-security-scanner-snyk
```

## Configuration

### 1. Set Environment Variables

**Required:**

```bash
# Your Snyk API token
export SNYK_API_TOKEN="your-api-token-here"

# Your Snyk organization ID
export SNYK_ORG_ID="your-org-id-here"
```

**Optional:**

```bash
# Logging level (debug, info, warn, error)
export SNYK_LOG_LEVEL=info

# Custom Snyk API base URL (optional)
export SNYK_API_BASE_URL=https://api.snyk.io/rest

# Request timeout in milliseconds (default: 30000)
export SNYK_TIMEOUT_MS=30000

# Disable batch queries (default: false)
export SNYK_DISABLE_BATCH=false
```

### 2. Enable the Scanner

Add to your `bunfig.toml`:

```toml
[install.security]
scanner = "bun-security-scanner-snyk"
```

### 3. Secure Your Credentials

**Never commit API tokens to version control!**

Add to your `.env` file:

```bash
# .env
SNYK_API_TOKEN=your-api-token-here
SNYK_ORG_ID=your-org-id-here
```

Add `.env` to your `.gitignore`:

```
# .gitignore
.env
```

## How It Works

### Security Scanning Process

1. **Package Detection**: Bun provides ALL packages (including transitive deps) before installation
2. **Smart Deduplication**: Eliminates duplicate package@version queries
3. **PURL Conversion**: Converts packages to PURL format (`pkg:npm/package@version`)
4. **Batch Querying**: Uses Snyk REST API's `/orgs/{org_id}/packages/issues` endpoint
5. **Vulnerability Matching**: Matches vulnerabilities to installed versions
6. **Severity Assessment**: Analyzes Snyk severity levels and CVSS scores
7. **Advisory Generation**: Creates actionable security advisories
8. **Installation Control**: Blocks or warns based on severity

### Advisory Levels

The scanner generates two types of security advisories:

#### Fatal (Installation Blocked)
- **Snyk Severity**: CRITICAL or HIGH
- **CVSS Score**: ≥ 7.0 (if available)
- **Action**: Installation is immediately blocked
- **Examples**: Remote code execution, privilege escalation, supply chain attacks

#### Warning (User Prompted)
- **Snyk Severity**: MEDIUM or LOW
- **CVSS Score**: < 7.0
- **Action**: User is prompted to continue or cancel
- **Examples**: Denial of service, information disclosure

## Usage

### Automatic Scanning

Once configured, the scanner runs automatically during:

```bash
bun install
bun add package-name
bun update
```

### Manual Testing (CLI)

Test specific packages:

```bash
# Test a single package
bun run src/cli.ts test lodash@4.17.20

# Test multiple packages
bun run src/cli.ts test express@4.18.0 axios@1.5.0

# Scan from package.json
bun run src/cli.ts scan ./package.json
```

## Example Output

### Clean Installation

```bash
$ bun install
[2025-01-27T10:00:00.000Z] SNYK-INFO: Starting Snyk scan for 150 packages
[2025-01-27T10:00:00.500Z] SNYK-INFO: Scanning 150 unique packages (150 total)
[2025-01-27T10:00:02.000Z] SNYK-INFO: Found 0 vulnerabilities
[2025-01-27T10:00:02.001Z] SNYK-INFO: Snyk scan completed: 0 advisories found for 150 packages
```

### Vulnerability Detected

```bash
$ bun add event-stream@3.3.6
[2025-01-27T10:00:00.000Z] SNYK-INFO: Starting Snyk scan for 1 packages
🔴 FATAL: event-stream@3.3.6
   Description: Malicious package - contains code that steals credentials
   Severity: CRITICAL
   URL: https://security.snyk.io/vuln/SNYK-JS-EVENTSTREAM-...

⚠️  Installation blocked due to critical security vulnerability
```

## Troubleshooting

### Error: Snyk API credentials not configured

**Cause**: Missing `SNYK_API_TOKEN` or `SNYK_ORG_ID` environment variables.

**Solution**:
1. Verify environment variables are set: `echo $SNYK_API_TOKEN`
2. Check your shell profile (`.bashrc`, `.zshrc`, etc.)
3. If using `.env` file, ensure it's loaded

### Error: Rate limit exceeded

**Cause**: Exceeded Snyk API rate limit (180 requests/minute).

**Solution**:
- Wait for the rate limit to reset (typically 1 minute)
- Reduce the number of packages being scanned
- The scanner will automatically retry with exponential backoff

### Error: Snyk API returned 401

**Cause**: Invalid or expired API token.

**Solution**:
1. Generate a new API token: [https://docs.snyk.io/snyk-api/authentication-for-api](https://docs.snyk.io/snyk-api/authentication-for-api)
2. Update your `SNYK_API_TOKEN` environment variable

### Error: Snyk API returned 404

**Cause**: Invalid Organization ID or endpoint not available.

**Solution**:
1. Verify your Organization ID: [https://app.snyk.io/](https://app.snyk.io/)
2. Ensure your Snyk plan supports the REST API
3. Contact Snyk support if the issue persists

### Error: Organization is not allowed to perform this action (403 Forbidden)

**Cause**: Your Snyk plan does not have access to the REST API endpoint used by this scanner. This scanner requires a **Snyk Enterprise plan**.

**Error Code**: `SNYK-OSSI-1040`

**Solution**:

This scanner uses the Snyk REST API endpoint `POST /rest/orgs/{org_id}/packages/issues`, which is only available on **Snyk Enterprise plans**.

**Don't have an Enterprise plan?** Switch to the free alternative:

```bash
# Remove this scanner
bun remove bun-security-scanner-snyk

# Install the OSV-based scanner (free, no account required)
bun add -d @bun-security-scanner/osv
```

Update your `bunfig.toml`:
```toml
[install.security]
scanner = "@bun-security-scanner/osv"
```

The OSV scanner is free, requires no API credentials, and works for everyone. Learn more: [@bun-security-scanner/osv](https://www.npmjs.com/package/@bun-security-scanner/osv)

### Scanner Not Running

**Check Configuration**:
```bash
# Verify bunfig.toml
cat bunfig.toml

# Should contain:
# [install.security]
# scanner = "bun-security-scanner-snyk"
```

### Enable Debug Logging

```bash
export SNYK_LOG_LEVEL=debug
bun install
```

## API Rate Limits

Snyk REST API has the following rate limits:

- **Rate Limit**: 180 requests per minute per user
- **Batch Size**: 100 packages per request (configurable)
- **Retry Strategy**: Automatic exponential backoff with `Retry-After` header support

The scanner automatically handles rate limits with intelligent batching and retry logic.

## Security Considerations

### API Token Security

- **Never commit tokens**: Use `.env` files and add to `.gitignore`
- **Rotate tokens regularly**: Generate new tokens periodically
- **Use organization tokens**: Avoid using personal API tokens in CI/CD
- **Restrict permissions**: Use tokens with minimal required permissions

### Scanner Fail-Safe

The scanner is designed with a fail-safe approach:

- **Never blocks on errors**: Scanner failures don't prevent installation
- **Logs all errors**: All failures are logged for debugging
- **Continues on partial failure**: If one batch fails, others continue
- **Graceful degradation**: Handles API outages without breaking installs

## Development

### Prerequisites

- [Bun](https://bun.sh/) >= 1.0.0
- Snyk API Token (for testing)
- Snyk Organization ID (for testing)

### Setup

```bash
# Clone repository
git clone https://github.com/your-org/bun-security-scanner-snyk
cd bun-security-scanner-snyk

# Install dependencies
bun install

# Set up environment variables
cp .env.example .env
# Edit .env with your Snyk credentials

# Run tests (unit tests don't require API token)
bun test tests/purl.test.ts
bun test tests/severity.test.ts

# Run integration tests (requires API token)
export SNYK_API_TOKEN="your-token"
export SNYK_ORG_ID="your-org-id"
bun test tests/scanner.test.ts
```

### Project Structure

```
src/
├── index.ts        # Main scanner entry point
├── client.ts       # Snyk API client
├── schema.ts       # Zod schemas for API responses
├── processor.ts    # Vulnerability processing logic
├── severity.ts     # Severity assessment logic
├── purl.ts         # PURL conversion utilities
├── logger.ts       # Structured logging
├── constants.ts    # Configuration constants
├── retry.ts        # Retry logic with exponential backoff
└── cli.ts          # CLI interface for testing

tests/
├── purl.test.ts    # PURL conversion tests
├── severity.test.ts # Severity mapping tests
└── ...             # Other test files
```

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details.

### Development Workflow

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Run linter: `bun run lint`
6. Run tests: `bun test`
7. Submit a pull request

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Bun](https://bun.sh/) - Fast all-in-one JavaScript runtime
- [Snyk](https://snyk.io/) - Developer security platform
- [Zod](https://zod.dev/) - TypeScript-first schema validation
- Built with [Claude Code](https://anthropic.com/claude-code)

## Related Projects

- [@bun-security-scanner/osv](https://npmjs.com/package/@bun-security-scanner/osv) - OSV.dev-based scanner (free alternative)

## Credits

This project is a fork and migration of [bun-osv-scanner](https://github.com/maloma7/bun-osv-scanner) by [maloma7](https://github.com/maloma7). The original project provided OSV.dev-based vulnerability scanning, and this version has been migrated to use the Snyk API while maintaining the same core functionality.

We are grateful for maloma7's original work, which laid the foundation for this scanner.

## Support

- **Issues**: [GitHub Issues](https://github.com/your-org/bun-security-scanner-snyk/issues)
- **Snyk Support**: [Snyk Support Portal](https://support.snyk.io/)
- **Bun Discord**: [https://bun.sh/discord](https://bun.sh/discord)

---

**⚠️ Important**: This scanner is designed to detect known vulnerabilities. It should be used as part of a comprehensive security strategy, not as the sole security measure.
