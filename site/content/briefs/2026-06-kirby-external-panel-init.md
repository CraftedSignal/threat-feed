---
title: Critical Kirby CMS Vulnerability Allows Remote Admin Account Creation via Reverse Proxy Headers (CVE-2026-54003)
slug: 2026-06-kirby-external-panel-init
description: 'A critical external initialization vulnerability (CVE-2026-54003) in Kirby CMS allows unauthenticated attackers to create an initial admin account on sites running behind a reverse proxy, specifically when the proxy utilizes `Forwarded: for=...`, `X-Client-IP`, or `X-Real-IP` headers, bypassing Kirby''s `isLocal` check and enabling remote Panel installation with full administrative access.'
date: "2026-06-18T15:18:49Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - web-vulnerability
  - cms
  - initial-access
  - privilege-escalation
  - kirby
vendors:
  - Kirby
products:
  - Kirby CMS (<= 4.9.3)
  - Kirby CMS (>= 5.0.0-alpha.1, <= 5.4.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136
    technique_name: ""
references:
  - https://github.com/advisories/GHSA-whxw-24jc-cwmv
rules:
  - title: Detects CVE-2026-54003 Exploitation - Kirby Remote Panel Init via Forwarded Header
    description: 'Detects exploitation attempts for CVE-2026-54003 in Kirby CMS where an attacker uses the ''Forwarded: for=...'' HTTP header to bypass the local IP check and perform remote Panel installation.'
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detects CVE-2026-54003 Exploitation - Kirby Remote Panel Init via X-Client-IP / X-Real-IP Headers
    description: Detects exploitation attempts for CVE-2026-54003 in Kirby CMS where an attacker uses 'X-Client-IP' or 'X-Real-IP' HTTP headers to bypass the local IP check and perform remote Panel installation.
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

A critical vulnerability, tracked as CVE-2026-54003, affects Kirby CMS versions up to 4.9.3 and from 5.0.0-alpha.1 to 5.4.3. This flaw, dubbed "External Initialization," enables unauthenticated remote attackers to create the initial administrative user account, effectively installing the Kirby Panel with full control over the CMS. The vulnerability arises in specific configurations where Kirby sites, without any configured user accounts, operate behind a reverse proxy that uses the `Forwarded: for=...`, `X-Client-IP`, or `X-Real-IP` HTTP headers. Kirby's `isLocal` check, designed to prevent remote installation, failed to properly account for these headers, leading it to incorrectly assume a remote connection was local. This misidentification grants an attacker the ability to bypass security controls and seize control of the Kirby instance.

## Attack Chain

1.  **Reconnaissance**: Attacker identifies a publicly accessible Kirby CMS instance lacking any configured user accounts, typically indicated by a redirect to the installation wizard upon accessing the Panel URL (`/panel`).
2.  **Reverse Proxy Identification**: Attacker determines that the target Kirby instance is fronted by a reverse proxy that uses `Forwarded: for=...`, `X-Client-IP`, or `X-Real-IP` headers for client IP forwarding.
3.  **Craft Malicious Request**: Attacker crafts an HTTP POST request to the Kirby Panel installation endpoint (e.g., `/api/system/install` or similar, depending on Kirby version and setup), including a forged `Forwarded`, `X-Client-IP`, or `X-Real-IP` header set to a local IP address (e.g., `127.0.0.1`).
4.  **Bypass `isLocal` Check**: The crafted request containing the local IP in the vulnerable header is forwarded by the reverse proxy to the Kirby backend. Kirby's `isLocal` check misinterprets the request as originating from a local source due to the forged header.
5.  **Initial Admin Account Creation**: The Kirby application proceeds with the installation process, allowing the attacker to provide desired credentials (username, password, email) for a new administrator account via the HTTP POST body.
6.  **Administrator Access**: Upon successful submission, the attacker-defined administrator account is created, granting full administrative control over the Kirby CMS instance.
7.  **Post-Exploitation**: The attacker can now perform any actions available to an administrator, including content modification, data exfiltration, plugin installation, or further system compromise.

## Impact

Successful exploitation of CVE-2026-54003 grants unauthenticated attackers full administrative control over the affected Kirby CMS instance. This directly leads to complete compromise of the website, allowing for arbitrary content modification, defacement, data theft (including user information if stored), and potentially the injection of malicious code or backdoors into the web application. Given Kirby's use in various industries for content management, the potential victim scope includes any organization or individual utilizing unpatched Kirby versions behind specific reverse proxy configurations with no existing admin users. The vulnerability's criticality stems from the ease of exploitation and the immediate elevation to administrative privileges.

## Recommendation

*   **Patch CVE-2026-54003 immediately**: Update Kirby CMS to version `4.9.4`, `5.4.4`, or a later patched version as detailed in the advisory.
*   **Deploy the provided Sigma rules**: Implement the `Detects CVE-2026-54003 Exploitation - Kirby Remote Panel Init` rules to your SIEM to identify attempts to exploit this vulnerability.
*   **Configure Workarounds**: If immediate patching is not feasible, perform the Panel installation yourself by creating an initial admin account. This disables the vulnerable installation code.
*   **Disable Panel API**: As an alternative workaround, if the Panel is not needed, disable the REST API with the `'api' => false` option in `config.php` to prevent access to the installation endpoint.
*   **Review Reverse Proxy Configuration**: Ensure your reverse proxy is configured to properly handle `X-Forwarded-For` or `Client-IP` headers if possible, or verify that `Forwarded: for=...`, `X-Client-IP`, and `X-Real-IP` are not inadvertently exposing internal IP addresses or being spoofed.
