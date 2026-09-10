---
title: Open WebUI Same-Origin XSS via Terminal Port Preview
slug: 2026-09-open-webui-xss
description: An insecure sandbox configuration in the Open WebUI terminal port preview feature allows authenticated users to execute arbitrary JavaScript in the application's origin, leading to session token theft and account takeover.
date: "2026-09-10T18:53:33Z"
lastmod: "2026-09-10T18:54:02Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:openwebui:open_webui:0.8.11:*:*:*:*:*:*:*
  - cpe:2.3:a:openwebui:open_webui:0.11.0:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - xss
  - session-theft
  - web-application
  - ssrf
  - cve-2026-87996
  - vulnerability
  - denial-of-service
  - cloud
vendors:
  - Open WebUI
products:
  - Open WebUI (0.8.11-0.11.0)
  - Open WebUI (0.9.6 - 0.11.0)
  - Open WebUI (0.10.0-0.11.0)
  - Open WebUI (< 0.11.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Any authenticated user with access to a shared terminal server could get script of their choosing to run in the Open WebUI origin itself.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1539
    technique_name: Steal Web Session Cookie
    evidence: The previewed page runs in the application origin, so it can reach the parent window, read the session token out of localStorage and exfiltrate it.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1537
    technique_name: Transfer Data to Cloud Account
    evidence: On a cloud host with IMDSv1 reachable, that is enough to take instance IAM credentials.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: An ordinary user removes instance-wide configuration that only administrators can create or manage.
    confidence_band: high
cves:
  - id: CVE-2026-87995
    cvss: 8.7
references:
  - https://github.com/advisories/GHSA-jmc6-2wr8-h3wj
  - https://github.com/advisories/GHSA-4v28-j6q3-5m4r
  - https://github.com/open-webui/open-webui/commit/27402ff21
  - https://github.com/advisories/GHSA-2724-6cpj-gf3v
  - https://github.com/open-webui/open-webui/pull/28113
  - https://github.com/advisories/GHSA-34r3-9m95-vq73
  - https://github.com/open-webui/open-webui/pull/27823
rules:
  - title: Detect CVE-2026-87998 Exploitation - Unauthorized Knowledge Base Deletion
    description: Detects potentially unauthorized attempts to delete knowledge bases by monitoring DELETE requests to the /api/v1/knowledge endpoint.
    platform: sigma
    severity: high
    tactics:
      - impact
    data_sources:
      - webserver
  - title: Detects CVE-2026-87999 Exploitation - Unauthorized SSRF Attempt
    description: Detects unauthorized SSRF attempts targeting common internal/platform IP addresses via the Open WebUI web retrieval API endpoint.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Upgrade Open WebUI to version 0.11.1
      owner: IT Operations
      due: 48h
      evidence: Fixed in 0.11.1 by 54d7a2237.
  mitigation_plan:
    - priority: immediate
      action: Configure restrictive CSP headers via TERMINAL_PROXY_HEADERS
      owner: IT Operations
      addresses: CVE-2026-87995
      evidence: An operator who had already set a restrictive Content-Security-Policy through either was not exposed.
updates:
  - at: "2026-09-10T18:53:42Z"
    level: L1
    summary: added coverage for Open WebUI (0.9.6 - 0.11.0)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-4v28-j6q3-5m4r
  - at: "2026-09-10T18:53:51Z"
    level: L1
    summary: 'added detection rule: Detect CVE-2026-87998 Exploitation - Unauthorized Knowledge Base Deletion'
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-2724-6cpj-gf3v
  - at: "2026-09-10T18:54:02Z"
    level: L2
    summary: 'added detection rule: Detects CVE-2026-87999 Exploitation - Unauthorized SSRF Attempt'
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-34r3-9m95-vq73
---

Open WebUI versions 0.8.11 through 0.11.0 contain a high-severity Cross-Site Scripting (XSS) vulnerability (CVE-2026-87995) within the terminal port-preview component. The application renders content from a terminal connection inside an iframe; however, the sandbox attribute for this iframe incorrectly included the `allow-same-origin` directive. Because the terminal proxy is served from the same origin as the primary application, this configuration effectively disables iframe isolation. 

An authenticated attacker with access to a shared terminal server can host a malicious HTML page on a port. When an unsuspecting user views this port via the Open WebUI terminal preview, the attacker-supplied script executes within the application origin. This permits the script to access `localStorage`, extract sensitive session tokens, and perform actions on behalf of the victim, leading to full account takeover. The vulnerability persists unless the user has manually configured restrictive Content Security Policy (CSP) headers or utilized a terminal connection with an external URL, which forces a cross-origin boundary.

## Attack Chain

1. Attacker obtains authenticated access to a shared terminal server environment managed by the Open WebUI instance.
2. Attacker deploys a malicious HTML file or script on a reachable port within that terminal server environment.
3. Attacker waits for a victim user (potentially an administrator) to open the Open WebUI file navigator.
4. Victim user navigates to the port list and selects the attacker-controlled port for preview.
5. Open WebUI renders the attacker's content within an iframe using the insecure `allow-same-origin` and `allow-scripts` sandbox flags.
6. Malicious script executes in the parent application context and accesses `window.parent.localStorage`.
7. Script exfiltrates the victim's session token to an attacker-controlled external server.
8. Attacker uses the stolen session token to assume the victim's identity and perform unauthorized operations, such as executing server-side code via Functions.

## Impact

Successful exploitation results in total account takeover of the victim. If the compromised victim holds administrative privileges or permissions related to `workspace.functions`, the attacker can escalate to server-side code execution. The attack is limited to deployments where `TERMINAL_SERVER_CONNECTIONS` are configured and shared between users.

## Recommendation

Upgrade Open WebUI to version 0.11.1 or later immediately to resolve CVE-2026-87995. Ensure that the `terminalPreviewAllowSameOrigin` user setting remains disabled, which is the default behavior in the patched version. For administrators who cannot upgrade immediately, verify that a restrictive Content Security Policy (CSP) is applied via the `TERMINAL_PROXY_HEADERS` configuration to mitigate the risk of script exfiltration.
