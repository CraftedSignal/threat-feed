---
title: Stored XSS Vulnerability in @apostrophecms/seo
slug: 2026-08-apostrophecms-xss
description: An authenticated Stored XSS vulnerability in the @apostrophecms/seo package (CVE-2026-53608) allows editors to inject malicious JavaScript into script tags, enabling session theft and unauthorized code execution for all site visitors.
date: "2026-08-01T01:47:48Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - ApostropheCMS
products:
  - '@apostrophecms/seo'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Any user with editor-level access (the default role for content managers) can set these fields to a malicious value, resulting in stored XSS.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The @apostrophecms/seo package injects the Google Analytics Tracking ID and Google Tag Manager ID directly into <script> tag bodies.
    confidence_band: high
cves:
  - id: CVE-2026-53608
    cvss: 8.7
    epss: 0.0021
references:
  - https://github.com/advisories/GHSA-wf43-fpp3-cf65
  - https://nvd.nist.gov/vuln/detail/CVE-2026-53608
rules:
  - title: Detect CVE-2026-53608 Exploitation - Malicious Script Injection in Global Config
    description: Detects exploitation of CVE-2026-53608 by monitoring PATCH requests to the global configuration API containing common XSS vectors in tracking ID fields.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1059.003
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

The @apostrophecms/seo package (versions <= 1.4.2) contains a high-severity stored Cross-Site Scripting (XSS) vulnerability, identified as CVE-2026-53608. The flaw exists because the module inserts Google Analytics (seoGoogleTrackingId) and Google Tag Manager (seoGoogleTagManager) IDs directly into &lt;script> templates without any input validation or output escaping. 

Because ApostropheCMS grants editor-level users the authority to modify the global site configuration, a compromised editor account or a malicious insider can inject arbitrary JavaScript payloads into these fields. The vulnerable data is then served verbatim to every visitor on every page of the website. This represents a significant risk for enterprises, as it facilitates full session hijacking of administrators, credential harvesting, and the potential for persistent site-wide malware delivery.

## Attack Chain

1. Attacker authenticates to the target application using valid editor-level credentials via the `/api/v1/@apostrophecms/login/login` endpoint.
2. Attacker performs an authorized GET request to `/api/v1/@apostrophecms/global` to retrieve the current global document ID.
3. Attacker identifies the `_id` field corresponding to the draft version of the global settings document.
4. Attacker uses a PATCH request to the `/api/v1/@apostrophecms/global/{GLOBAL_DRAFT_ID}` endpoint to overwrite the `seoGoogleTrackingId` field with a malicious payload (e.g., `G-FAKE'); alert(document.cookie); //`).
5. Attacker calls the `/api/v1/@apostrophecms/global/{GLOBAL_DRAFT_ID}/publish` endpoint to promote the malicious draft to production.
6. The application renders the payload inside a `<script>` tag within the page header.
7. Site visitors (including administrators) load the page, triggering the injected JavaScript in their browsers.
8. Attacker captures exfiltrated session tokens or credentials via a remote listener.

## Impact

Successful exploitation allows for complete compromise of site visitor sessions. Because the payload is stored globally, it executes on every page visit, providing an attacker with persistent access to the browser environment. This impacts the confidentiality and integrity of both the site visitors and the administrative user base, potentially leading to full administrative account takeover and unauthorized modification of site content.

## Recommendation

Prioritized actions for security and engineering teams:

- Update the `@apostrophecms/seo` package to a version that implements input validation and safe template rendering.
- Implement a strict Content Security Policy (CSP) that restricts script sources and forbids inline script execution to mitigate XSS impact.
- Review the permissions of the 'editor' role within ApostropheCMS to ensure that only trusted users have access to global configuration settings.
- Audit logs for PATCH/POST requests directed at the `/api/v1/@apostrophecms/global` endpoint to identify suspicious modifications to tracking IDs.
- Apply the validation logic proposed in the CVE-2026-53608 advisory (e.g., regex-based tracking ID verification) to any custom modules handling similar site-wide configurations.
