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

## V2 evidence collection

The scanner now performs at most three successful HTML fetches: the provided URL plus up to two links explicitly present in the returned HTML, restricted to the same origin. Each request revalidates DNS and pinned public IPs; redirects are independently validated. Secondary-page failures do not fail the initial report.

The report includes an evidence ledger with the observation's originating URL and reliability label. It reports technology evidence, the provenance of a reported PHP version, patch-version assessment, proxy indications and an evidence-completeness tally separately.

Owner-supplied information now accepts distribution, package release, web-serving SAPI and an optional advisory reference. This information is **not verified** and cannot be used by itself to mark the deployment patched. The full owner-verification workflow and automated vendor advisory matching are future work.

### Local validation

Run `npm install && npm test && npm run build` after pulling the changes. Network-dependent scans should be tested only against a website you're authorized to assess. No live site was scanned during this code update.

## CMS versions and historical hints

Public HTML now provides additional weak evidence: WordPress generator/version hints, selected WordPress core asset query versions, Drupal generator versions, other generator strings, and copyright years. Core CMS versions are linked to a curated, dated compatibility mapping from WordPress and Drupal documentation.

**Important:** CMS software compatibility is not the running PHP version. CSS/JS asset versions can be cache-busted or stale; copyright dates represent page content, not deployment age. These hints never cause a PHP2Shell finding to be classified as patched or affected.

Compatibility references:
- https://make.wordpress.org/core/handbook/references/php-compatibility-and-wordpress-versions/
- https://make.wordpress.org/hosting/handbook/compatibility/
- https://www.drupal.org/docs/getting-started/system-requirements/php-requirements

Mapping reviewed: October 22, 2026. Joomla version-specific requirements and other CMS products are not yet mapped.

## Administrator bulk assessments

1. Pull the repository and run `npm install`.
2. Copy `.env.example` to `.env` and set `ADMIN_PASSWORD` to your own 14+ character password. Set `ADMIN_SESSION_SECRET` to a random 32+ character value, for example by running `node -e "console.log(require('node:crypto').randomBytes(32).toString('hex'))"`. The existing `ADMIN_PASSWORD_HASH` format remains supported as an alternative.
3. Run `docker compose up --build` (or set the same environment variables before `npm run dev`).
4. Open **Administrator** in the application's left navigation and log in with your password.
5. Import a TXT file with one HTTPS website URL (or hostname) per line. There is no fixed website-count cap, though the import payload is limited to 1.5 MB and large batches take longer.
6. For every domain under your control, publish a TXT record with name `_php2shell-check.yourdomain.example` and the corresponding verification value shown in the administrator table. Click **Check TXT**.
7. Use **Verify all websites** to check the imported DNS TXT records sequentially, with progress displayed in the admin area. Use **Delete imported list** to clear all imported entries, tokens and results when no batch is running. Only DNS-verified domains can be batch-scanned. Use **Scan verified websites** to run sequential passive assessments. Progress refreshes automatically and results can be sorted by evidence confidence, completeness, PHP hints, assessment or domain. Export as CSV.

The example file `examples/100-synthetic-websites.txt` includes **100 fictional names under .invalid**, for UI/import testing only. They do not represent real clubs or businesses, cannot be resolved and cannot pass domain verification.

**Operational limitations:** Batch results and imported targets are stored in RAM, and are lost on server restart. This is an authenticated single-administrator MVP, not a multi-user platform. Runs one batch at a time, waits between domains and revalidates each DNS ownership token. The results list is not a ranking of confirmed vulnerabilities; evidence confidence is explicitly not exploit likelihood.

**Deployment security:** Set `ADMIN_COOKIE_SECURE=true` in `.env` when serving over HTTPS behind a correctly configured reverse proxy. The default is compatible with `http://localhost:8080` for local testing only. Deploy behind TLS, network egress controls and access restrictions; don't expose the admin on plain HTTP. With `ADMIN_PASSWORD`, the password is stored in plaintext in your local `.env` file and never embedded in frontend code. Keep that file private and use the salted `ADMIN_PASSWORD_HASH` alternative for deployments. CSRF protection currently relies on SameSite=Strict cookies; harden further before a public production deployment.
