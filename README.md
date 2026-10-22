# PHP2Shell Security Scanner

A responsive React + TypeScript dashboard with an Express API for **passive**, evidence-based PHP runtime assessment of CVE-2026-109618 and CVE-2026-109619.

## Start

```bash
docker compose up --build
```

Open **http://localhost:8080**.

For local development (Node.js 22+):

```bash
npm install
npm run dev
npm test
npm run build
```

Vite frontend: http://localhost:5173. Express API: http://localhost:3001.

## Implemented

- Public HTTPS scanning using low-impact GET requests
- DNS/IP public-address checks, pinned DNS resolution, checked HTTPS redirects, timeouts, response size limits, and per-IP rate limits
- PHP header fingerprints and common public CMS indicators
- Separate CVE findings, confidence caveats, potential impact and remediation
- Optional *owner-provided* PHP version (not a verified diagnostic or an active ownership-check feature)
- Local browser history, previous reports, JSON download, and PDF via browser print
- Version comparison, basic network-target validation, and report-generation tests

## Limitations

Passive observation **cannot prove either vulnerability is exploitable or that a runtime is patched**. A reported upstream version may differ from the active PHP worker, and distribution packages can include backported fixes. The owner input is a claim, not independently verified. A missing PHP header is never proof of safety. Results are not a substitute for package inventory and vendor advisory review.

No exploit probes, memory-corruption requests, brute force, hidden-endpoint enumeration, or command execution are implemented. Scanning is limited to standard HTTPS on publicly resolved addresses. Only scan targets you're authorized to assess.

The URL scanner needs an egress-restricted network in production; app-level safeguards alone are not a complete SSRF isolation boundary.

## Security intelligence

Compare patch levels against the latest advisories before relying on any result:

- https://github.com/NCSC-NL/php2shell
- https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
- https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp

Source references reviewed: 2026-10-22.

**Not yet implemented:** DNS TXT/HTTP token-based ownership verification, OS vendor backport database, direct PDF file generation, authenticated owner mode and persistent server-side history.
