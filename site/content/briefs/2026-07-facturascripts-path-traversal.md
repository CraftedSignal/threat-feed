---
title: FacturaScripts Unauthenticated Path Traversal Vulnerability (CVE-2026-45693)
slug: 2026-07-facturascripts-path-traversal
description: FacturaScripts contains an unauthenticated path traversal vulnerability (CVE-2026-45693) in its static file controllers, allowing attackers to bypass authorization by manipulating URLs with `../` segments to read sensitive files like invoices and database backups from the application's filesystem without authentication.
date: "2026-07-14T19:24:20Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - web-application
  - data-leakage
  - unauthenticated-access
vendors:
  - FacturaScripts
products:
  - FacturaScripts (<= 2026.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The static file controllers in FacturaScripts decide whether a request is authorized by looking at the URL string instead of the canonical filesystem path...This makes any file inside the FacturaScripts installation readable without authentication.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: 'This makes any file inside the FacturaScripts installation readable...In practice this leaks the documents the application is specifically designed to protect: customer invoices, supplier invoices, document attachments and database backups stored under `MyFiles/Private/` and other non-public subfolders.'
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-cv65-7cg8-r623
rules:
  - title: Detects CVE-2026-45693 Exploitation - Path Traversal via /Plugins/
    description: Detects CVE-2026-45693 exploitation - unauthenticated path traversal attempts targeting FacturaScripts via the /Plugins/ route, indicated by '..' or URL-encoded variants in the URI after '/Plugins/'.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detects CVE-2026-45693 Exploitation - Path Traversal via /MyFiles/Public/
    description: Detects CVE-2026-45693 exploitation - unauthenticated path traversal attempts targeting FacturaScripts via the /MyFiles/Public/ route, indicated by '..' or URL-encoded variants in the URI after '/MyFiles/Public/'.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

FacturaScripts versions up to and including v2026.2 are vulnerable to an unauthenticated path traversal (CVE-2026-45693) in its static file controllers, specifically `Core/Controller/Files.php` and `Core/Controller/Myfiles.php`. This vulnerability allows attackers to read sensitive files from the FacturaScripts installation without authentication. The flaw arises because the application's controllers incorrectly authorize file access based on URL string prefixes rather than resolving the canonical filesystem path. By injecting path traversal sequences like `../` into URLs that begin with allow-listed folders (e.g., `/Plugins/` or `/MyFiles/Public/`), an attacker can access files outside the intended directories. This can lead to the unauthorized disclosure of confidential data such as customer invoices, supplier invoices, document attachments, and database backups stored under `MyFiles/Private/` and other non-public subfolders. The vulnerability was confirmed on commit `de01369` (master, 2026-05-11) and tag `v2026.2` using PHP 8.0.30 on Apache 2.4.56.

## Attack Chain

1. An unauthenticated attacker sends an HTTP GET request to a vulnerable FacturaScripts instance, targeting a static file controller (e.g., `Core/Controller/Files.php`).
2. The request URL includes a path traversal sequence such as `/Plugins/../MyFiles/Private/invoice.pdf` or `/MyFiles/Public/../Private/backup.sql`, potentially using URL-encoded characters like `%2e%2e`.
3. The vulnerable controller receives the HTTP request and performs a prefix check on the raw URL string (e.g., `strpos($url, '/Plugins/') === 0`), which incorrectly grants initial authorization.
4. The application's underlying filesystem functions (e.g., `is_file()`) then resolve the `../` segment, effectively pointing to a file in a different, unauthorized directory (e.g., `MyFiles/Private/invoice.pdf`).
5. The `isFileSafe()` function checks the file's extension (e.g., `.pdf`, `.sql`), which if on the allow-list, permits the file to be served.
6. For the `/MyFiles/Public/../` path, the `Myfiles.php` controller specifically bypasses the `myft` token check due to the `/MyFiles/Public/` prefix, despite the actual file being in a restricted `Private` directory.
7. The application serves the sensitive file (e.g., customer invoice, database backup) to the unauthenticated attacker via the HTTP response.
8. The attacker successfully exfiltrates internal documents or data that should normally be protected.

## Impact

Successful exploitation of CVE-2026-45693 leads to the unauthorized disclosure of sensitive business data without requiring any authentication. This includes critical financial and operational documents such as customer and supplier invoices, detailed document attachments, and potentially entire database backups (SQL files). Such information could be used for corporate espionage, financial fraud, or further targeted attacks. The vulnerability affects any FacturaScripts installation up to v2026.2. While the vulnerability does not directly lead to remote code execution due to limitations on file extensions that can be served, the exposure of confidential business records poses a significant risk to data privacy and regulatory compliance.

## Recommendation

* Deploy the Sigma rules `Detects CVE-2026-45693 Exploitation - Path Traversal via /Plugins/` and `Detects CVE-2026-45693 Exploitation - Path Traversal via /MyFiles/Public/` to your SIEM and tune for your environment to identify exploitation attempts.
* Monitor web server access logs (category `webserver`) for HTTP GET requests containing path traversal sequences (e.g., `../`, `%2e%2e`) in the `cs-uri-stem` or `cs-uri-query` fields, especially targeting `/Plugins/*` or `/MyFiles/Public/*` routes.
* Patch FacturaScripts instances to a version beyond v2026.2 that addresses CVE-2026-45693 as soon as a fix is available from the vendor.
