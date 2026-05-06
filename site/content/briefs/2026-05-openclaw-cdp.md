---
title: OpenClaw Improper Network Binding Leads to Unauthorized CDP Access (CVE-2026-43581)
slug: 2026-05-openclaw-cdp
description: OpenClaw before 2026.4.10 contains an improper network binding vulnerability (CVE-2026-43581) that exposes the Chrome DevTools Protocol (CDP) on 0.0.0.0, allowing attackers to access the DevTools protocol outside intended local sandbox boundaries.
date: "2026-05-06T20:16:33Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - cve
  - network-binding
  - sandbox-escape
vendors:
  - OpenClaw
products:
  - OpenClaw (< 2026.4.10)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-43581
    cvss: 9.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-43581
  - https://github.com/openclaw/openclaw/commit/fbf11ebdb7110632f93926d0ac7b48f04cb44d77
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-525j-hqq2-66r4
  - https://www.vulncheck.com/advisories/openclaw-chrome-devtools-protocol-exposure-via-overly-broad-cdp-relay-binding
rules:
  - title: Detect OpenClaw CDP Exposure
    description: Detects instances where OpenClaw exposes the Chrome DevTools Protocol (CDP) on all interfaces (0.0.0.0), indicating a vulnerable configuration.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - linux
  - title: Detect Unauthorized CDP Connections
    description: Detects network connections to the Chrome DevTools Protocol (CDP) port (9222) from unauthorized sources.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

OpenClaw, a sandbox browser, prior to version 2026.4.10, is vulnerable to an improper network binding that exposes the Chrome DevTools Protocol (CDP) on all interfaces (0.0.0.0). This vulnerability, identified as CVE-2026-43581, stems from an overly broad binding configuration in the CDP relay component. This allows unauthorized network access to the DevTools protocol from outside the intended local sandbox environment. Successful exploitation allows attackers to interact with the browser instance, potentially leading to sensitive information disclosure or remote code execution within the sandboxed environment. Defenders need to ensure OpenClaw instances are updated to version 2026.4.10 or later.

## Attack Chain

1.  Attacker identifies a vulnerable OpenClaw instance running a version prior to 2026.4.10 with the CDP relay exposed on 0.0.0.0.
2.  The attacker scans the network for exposed CDP ports (typically port 9222).
3.  Attacker establishes a network connection to the exposed CDP port.
4.  The attacker uses the Chrome DevTools Protocol to inspect the sandboxed browser.
5.  Attacker interacts with the browser through CDP, potentially accessing loaded web pages and associated data.
6.  The attacker leverages CDP commands to execute JavaScript code within the sandboxed browser context.
7.  The attacker exploits vulnerabilities within the loaded web pages, using CDP as a conduit.
8.  Attacker gains unauthorized access to sensitive information or achieves remote code execution within the sandbox, potentially escaping the sandbox depending on its configuration.

## Impact

Successful exploitation of CVE-2026-43581 allows attackers to bypass the intended security restrictions of the OpenClaw sandbox. This can lead to the exposure of sensitive data processed within the browser, such as credentials, session tokens, or other confidential information. Furthermore, by leveraging the Chrome DevTools Protocol, an attacker could potentially execute arbitrary code within the sandbox environment. The vulnerability has a CVSS v3.1 base score of 9.6, indicating a critical severity.

## Recommendation

*   Upgrade all OpenClaw installations to version 2026.4.10 or later to remediate CVE-2026-43581.
*   Deploy the Sigma rule `Detect OpenClaw CDP Exposure` to identify instances where the Chrome DevTools Protocol is exposed on an overly broad interface.
*   Monitor network connections to the default CDP port (9222) using the Sigma rule `Detect Unauthorized CDP Connections`.
*   If upgrading is not immediately feasible, implement network segmentation to restrict access to the CDP port (9222) to trusted sources only.
