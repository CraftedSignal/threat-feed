---
title: Unauthenticated SQL Execution Vulnerability in Recce OSS Server (CVE-2026-49360)
slug: 2026-07-recce-unauthenticated-sql-rce
description: Recce OSS server deployments are vulnerable to unauthenticated SQL execution via the query run API when configured with a DuckDB-backed project, allowing attackers to use DuckDB filesystem primitives to read and write arbitrary files accessible to the server process, potentially leading to data disclosure, tampering, or stored XSS.
date: "2026-07-03T11:09:54Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-vulnerability
  - sql-injection
  - file-read-write
  - rce
  - data-exfiltration
  - recce
vendors:
  - Recce
products:
  - recce (<= 1.49.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Recce OSS server deployments that expose the server to an untrusted network without authentication are vulnerable to unauthenticated SQL execution through the query run API.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: unauthenticated SQL execution through the query run API... attacker can use DuckDB filesystem primitives to read and write files
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: attacker can use DuckDB filesystem primitives to read and write files accessible to the Recce server process
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-rh62-j648-g5qc
  - https://nvd.nist.gov/vuln/detail/CVE-2026-49360
rules:
  - title: Detect CVE-2026-49360 Exploitation - Recce DuckDB File Operations
    description: Detects exploitation attempts for CVE-2026-49360 in Recce OSS server, specifically looking for unauthenticated web requests to API endpoints that contain DuckDB file system primitives for file read/write operations.
    platform: sigma
    severity: high
    tactics:
      - discovery
      - execution
      - initial_access
    techniques:
      - T1059
      - T1083
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

A critical unauthenticated SQL execution vulnerability, identified as CVE-2026-49360, has been discovered in Recce OSS server versions up to `v1.49.0`. This flaw specifically affects deployments where the Recce server is exposed to an untrusted network without authentication and is configured to use a DuckDB-backed project. Exploitation allows an attacker to leverage DuckDB filesystem primitives through the `query run API` to perform arbitrary local file read and write operations on the server. The implications are significant, ranging from sensitive data disclosure and tampering with Recce/dbt artifacts to potential stored Cross-Site Scripting (XSS) via modification of browser-served static files. The severity of impact is heightened if Recce is running with elevated privileges (e.g., as root), as file access would occur with corresponding permissions. The vulnerability was responsibly reported by Sitampan (@hxcbtc) and patched in Recce `v1.50.0`.

## Attack Chain

1.  An unauthenticated attacker identifies a vulnerable Recce OSS server (`<= v1.49.0`) exposed to an untrusted network.
2.  The attacker sends a specially crafted HTTP request to the Recce server's `query run API` endpoint.
3.  The request payload contains SQL commands leveraging DuckDB syntax and filesystem primitives, bypassing authentication.
4.  The Recce server, running with a DuckDB-backed project, processes the malicious SQL query.
5.  The embedded DuckDB filesystem functions (e.g., `READ_CSV`, `COPY`) are executed to access the server's local file system.
6.  The attacker reads sensitive local files (e.g., `/etc/passwd`, database credentials, application configuration).
7.  Alternatively, the attacker writes malicious content to server-accessible paths (e.g., modifying static files for stored XSS or corrupting application files).
8.  Successful exploitation leads to data exfiltration, system compromise, or persistent defacement, with potential root privileges if the Recce process is running as root.

## Impact

The observed impact of this vulnerability depends heavily on the Recce server's deployment configuration. Attackers can achieve unauthorized disclosure of local files, potentially exposing sensitive data, configuration files, or credentials accessible to the Recce server process. Tampering with Recce or dbt artifacts could lead to data integrity issues or supply chain attacks. Modification of browser-served static files might result in stored Cross-Site Scripting (XSS), affecting users interacting with the Recce interface. Furthermore, if application files themselves are writable, attackers could modify core application logic. If the Recce server is running with root privileges (a misconfiguration), the file access can occur with full root capabilities, leading to complete host or container compromise.

## Recommendation

*   **Patch CVE-2026-49360 immediately**: Upgrade all Recce server deployments to `v1.50.0` or later, as specified in the patches section of the advisory.
*   **Implement network access controls**: Ensure `recce server` is not exposed to the public internet or any untrusted network, as mentioned in the workarounds section.
*   **Deploy behind an authenticated proxy**: Place Recce behind an authenticated reverse proxy or VPN to enforce access control, as suggested in the workarounds section.
*   **Enforce least privilege**: Run the Recce server process as a non-root user to limit the scope of file access in case of compromise, as advised in the workarounds section.
*   **Restrict file system access**: Configure the application's filesystem as read-only where possible, and ensure sensitive files or credentials are not accessible to the Recce process.
*   **Deploy the Sigma rule below**: Use the provided `Detect CVE-2026-49360 Exploitation - Recce DuckDB File Operations` rule in your SIEM to identify attempts to exploit this vulnerability.
