---
title: Budibase Stored Cross-Site Scripting Vulnerability (CVE-2026-35218)
slug: 2026-04-budibase-xss
description: A stored cross-site scripting (XSS) vulnerability in Budibase versions prior to 3.32.5 allows authenticated users with Builder access to inject malicious HTML payloads into entity names, leading to potential session cookie theft and account takeover when other Builder users open the Command Palette.
date: "2026-04-03T16:16:41Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - budibase
  - xss
  - cve-2026-35218
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-35218
    cvss: 8.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35218
rules:
  - title: Budibase Suspicious Command Palette HTML
    description: Detects potential XSS exploitation in Budibase by monitoring HTTP requests for the Command Palette that contain suspicious HTML tags in the query parameters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Budibase Suspicious Entity Creation with HTML
    description: Detects potential XSS exploitation in Budibase by monitoring HTTP requests related to entity creation that contain suspicious HTML tags in the request body.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Budibase, an open-source low-code platform, is vulnerable to a stored cross-site scripting (XSS) attack. Prior to version 3.32.5, the Builder Command Palette renders entity names (tables, views, queries, automations) unsanitized, using Svelte's {@html} directive. This allows an attacker with Builder access to inject arbitrary HTML into the names of database tables, views, queries, or automations. When a Builder-role user in the same workspace opens the Command Palette (Ctrl+K), the injected HTML payload is executed within their browser context. This execution can be leveraged to steal session cookies, leading to full account takeover. The vulnerability, identified as CVE-2026-35218, was patched in Budibase version 3.32.5. Defenders should prioritize upgrading to the patched version.

## Attack Chain

1. An attacker authenticates to a Budibase instance with Builder access.
2. The attacker creates or modifies a database table.
3. The attacker injects a malicious HTML payload (e.g., `<img src=x onerror=alert(document.domain)>`) into the table name via the Budibase Builder interface.
4. The attacker saves the modified table.
5. Another authenticated user with Builder access in the same workspace opens the Command Palette (Ctrl+K).
6. The Command Palette renders the table name containing the malicious HTML.
7. The user's browser executes the injected HTML, triggering the onerror event and executing JavaScript.
8. The JavaScript steals the user's session cookie and sends it to an attacker-controlled server.
9. The attacker uses the stolen session cookie to impersonate the victim user and gain full account access.

## Impact

Successful exploitation of this vulnerability can lead to the theft of sensitive user session cookies, allowing an attacker to impersonate legitimate users with Builder access. This can result in unauthorized modification of Budibase applications, exfiltration of sensitive data stored within Budibase, and further compromise of systems integrated with Budibase. The severity is high due to the ease of exploitation for authenticated users and the potential for complete account takeover.

## Recommendation

*   Upgrade Budibase to version 3.32.5 or later to remediate CVE-2026-35218.
*   Implement the Sigma rule `Budibase_Suspicious_Command_Palette_HTML` to detect potential exploitation attempts by monitoring HTTP activity related to the Command Palette.
*   Enable webserver logging to collect the data required by the Sigma rule `Budibase_Suspicious_Command_Palette_HTML`.
