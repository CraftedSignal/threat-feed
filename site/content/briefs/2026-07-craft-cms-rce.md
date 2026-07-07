---
title: Craft CMS Authenticated RCE (CVE-2026-55794) via Referer Header Twig Injection
slug: 2026-07-craft-cms-rce
description: An authenticated Remote Code Execution (RCE) vulnerability, CVE-2026-55794, affects Craft CMS versions 5.9.0 up to, but not including, 5.10.0, allowing a control panel user with entry editing permissions to exploit by injecting unsandboxed Twig code into the HTTP Referer header when saving an entry, leading to arbitrary code execution.
date: "2026-07-06T21:38:43Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - rce
  - web-application
  - craft-cms
  - cve
  - authenticated-rce
vendors:
  - craftcms
products:
  - Craft CMS (>= 5.9.0, < 5.10.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Control panel users with the ability to edit entries can execute unsandboxed Twig code via the HTTP Referrer header.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: Control panel access
    confidence_band: high
cves:
  - id: CVE-2026-55794
    epss: 0.00293
references:
  - https://github.com/advisories/GHSA-f74w-488g-8x5r
  - https://github.com/craftcms/cms/pull/18680
rules:
  - title: Detects CVE-2026-55794 Exploitation — Craft CMS Referer Twig Injection
    description: Detects exploitation attempts of CVE-2026-55794 in Craft CMS by identifying unsandboxed Twig template injection patterns in the HTTP Referer header.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059
      - T1078.003
    data_sources:
      - webserver
rules_count: 1
---

A high-severity authenticated Remote Code Execution (RCE) vulnerability, tracked as CVE-2026-55794, has been identified in Craft CMS versions 5.9.0 through 5.9.x. The flaw allows authenticated control panel users who possess permissions to edit entries to execute arbitrary Twig code on the underlying server. This occurs because the platform incorrectly processes user-controlled data within the HTTP `Referer` header as an unsandboxed Twig template during the entry-saving process. Attackers can manipulate this header to inject malicious Twig code, bypassing intended sandboxing mechanisms and achieving full RCE. The vulnerability is considered critical for affected installations as it grants server-level control to a compromised or malicious authenticated user. The issue has been addressed in Craft CMS 5.10.0, and immediate patching is recommended for all affected instances.

## Attack Chain

1.  An attacker gains or possesses authenticated access to the Craft CMS control panel with permissions to edit entries.
2.  The attacker initiates a process to save an existing entry or create a new one within the Craft CMS control panel.
3.  Prior to sending the save request, the attacker intercepts or crafts the HTTP request, specifically manipulating the `Referer` header.
4.  The attacker injects malicious, unsandboxed Twig code into the `Referer` header's value, designed to execute arbitrary commands.
5.  Craft CMS processes the `Referer` header value as part of generating a signed redirect URL, inadvertently compiling the attacker-controlled string as an unsandboxed Twig template using `renderObjectTemplate()`.
6.  The injected malicious Twig code is executed by the server-side template engine, leading to arbitrary command execution on the host.

## Impact

Successful exploitation of CVE-2026-55794 grants an authenticated attacker full Remote Code Execution (RCE) on the server hosting Craft CMS. This can lead to complete compromise of the web server and its associated data. Impact includes, but is not limited to, data exfiltration, website defacement, installation of backdoors, further lateral movement within the network, and complete system takeover. Organizations in any sector using affected Craft CMS versions are at risk of significant operational disruption and data breaches if this vulnerability is exploited.

## Recommendation

*   Immediately update Craft CMS to version 5.10.0 or higher to patch CVE-2026-55794.
*   Deploy the Sigma rule below to your SIEM to detect attempts at Twig injection via the `Referer` header.
*   Ensure web server logs (category `webserver`) are configured to capture full HTTP request headers, especially the `Referer` header, for effective detection.
