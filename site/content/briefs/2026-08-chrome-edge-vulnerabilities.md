---
title: Multiple Vulnerabilities in Google Chrome and Microsoft Edge
slug: 2026-08-chrome-edge-vulnerabilities
description: Multiple vulnerabilities in Google Chrome and Microsoft Edge allow remote, unauthenticated attackers to achieve arbitrary code execution, bypass sandbox protections, and perform information disclosure.
date: "2026-08-27T11:33:16Z"
lastmod: "2026-08-27T11:33:22Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*
  - cpe:2.3:o:fedoraproject:fedora:38:*:*:*:*:*:*:*
  - cpe:2.3:o:fedoraproject:fedora:39:*:*:*:*:*:*:*
  - cpe:2.3:o:fedoraproject:fedora:40:*:*:*:*:*:*:*
vendors:
  - Google
  - Microsoft
products:
  - Chrome
  - Edge
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Ein entfernter, anonymer Angreifer kann mehrere Schwachstellen in Google Chrome/Microsoft Edge ausnutzen, um beliebigen Programmcode auszuführen.
    confidence_band: high
cves:
  - id: CVE-2024-4671
    cvss: 9.6
    epss: 0.08348
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-0612
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-0420
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  mitigation_plan:
    - priority: immediate
      action: Deploy browser updates to latest versions for Chrome and Edge
      owner: IT Operations
      addresses: Multiple browser vulnerabilities
      evidence: Source advisory recommends updating to mitigate known flaws.
updates:
  - at: "2026-08-27T11:33:22Z"
    level: L2
    summary: added CVE-2024-4671
    sources:
      - bsi
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-0420
---

Multiple vulnerabilities have been identified in the Google Chrome and Microsoft Edge web browsers, both of which are based on the Chromium engine. These flaws allow a remote, unauthenticated attacker to exploit browser-based weaknesses to achieve arbitrary code execution, escape the browser's sandbox environment, and disclose sensitive information. While specific vulnerability identifiers were not detailed in the source advisory, these flaws represent a significant threat to browser security. Defenders should treat these as high-priority updates for all enterprise endpoints, as browser-based exploitation is a common vector for initial access and payload delivery.

## Impact

Successful exploitation of these vulnerabilities compromises the confidentiality, integrity, and availability of the browser session and potentially the underlying host system. In scenarios where sandbox escapes are achieved, an attacker can transition from browser-level control to host-level command execution, increasing the risk of full system compromise, data theft, and persistent malware installation.

## Recommendation

Prioritize the deployment of vendor-provided security updates for all versions of Google Chrome and Microsoft Edge within the environment. Ensure that auto-update mechanisms are functioning correctly across all managed endpoints to mitigate the risk of exploitation.
