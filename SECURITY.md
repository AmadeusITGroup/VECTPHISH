# Security Policy

## Supported usage

VECTPHISH is intended as an analyst-support tool for phishing campaign correlation and enrichment.

## Security model

VECTPHISH is designed primarily for local execution:

- Local application execution
- Local SQLite storage
- No telemetry collection
- No runtime internet requirement after local models are installed
- Optional local Ollama LLM execution

## Reporting a vulnerability

Please **do not open a public GitHub issue** for security vulnerabilities.

Security vulnerabilities should be reported privately using one of the following methods:

### Option 1 — GitHub Private Vulnerability Reporting

If private vulnerability reporting is enabled for this repository:

1. Open the **Security** tab of the VECTPHISH GitHub repository.
2. Select **Advisories**.
3. Click **Report a vulnerability**.
4. Provide the details of the vulnerability and submit the report privately.

### Option 2 — Email

You can also report a vulnerability by email to:

**opensource@amadeus.com**

Please include, where possible:

- A description of the vulnerability
- Steps to reproduce the issue
- The affected VECTPHISH version or commit
- Expected and observed behavior
- Potential security impact
- Relevant logs, screenshots, or proof-of-concept information

Please **do not include real phishing datasets, credentials, personal data, customer information, sensitive internal logs, or other confidential information** in the initial report.

## What to expect

After receiving a vulnerability report:

- **Acknowledgment:** We will acknowledge receipt of the report as soon as reasonably possible.
- **Assessment:** The vulnerability will be reviewed to determine its severity and impact.
- **Remediation:** Valid security issues will be prioritized based on their severity.
- **Disclosure:** Where appropriate, disclosure and remediation timelines will be coordinated with the reporter.

Security fixes may be published through a new release, release notes, and/or a GitHub Security Advisory.

## Responsible disclosure

We ask security researchers to:

- Report vulnerabilities privately before making them public.
- Allow reasonable time for investigation and remediation.
- Avoid accessing, modifying, or deleting data that does not belong to them.
- Avoid disrupting services or systems.
- Limit testing to what is necessary to demonstrate the vulnerability.

## Dependency vulnerabilities

VECTPHISH uses third-party dependencies that may occasionally contain security vulnerabilities.

If you discover a vulnerability in a dependency that affects VECTPHISH, please report it using the private reporting methods described above so that its impact can be assessed and an appropriate update can be coordinated.
