---
title: Path Traversal Vulnerability in MapSVG Plugin
slug: 2026-10-path-traversal-mapsvg
description: A path traversal vulnerability in the MapSVG plugin, tracked as CVE-2026-111398, allows unauthenticated attackers to read arbitrary files from the hosting server.
date: "2026-10-19T12:03:18Z"
lastmod: "2026-10-19T12:03:25Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:pt_norther_lights_production:mapsvg:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - path-traversal
  - cve
  - web-application
  - wordpress
  - vulnerability
  - rce
vendors:
  - PT Norther Lights Production
products:
  - MapSVG (<= 8.16.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The vulnerability allows an attacker to manipulate file paths to access files outside of the intended directory.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505.003
    technique_name: 'Server Software Component: Web Shell'
    evidence: 'This issue affects MapSVG: from n/a through 8.16.1... allows Upload a Web Shell to a Web Server.'
    confidence_band: high
cves:
  - id: CVE-2026-111398
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111398
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111406
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade MapSVG plugin to a version beyond 8.16.1
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-111398 advisory scope
  mitigation_plan:
    - priority: immediate
      action: Implement WAF rules to filter directory traversal sequences
      owner: SOC
      addresses: CVE-2026-111398
      evidence: Path traversal vulnerability mitigation
updates:
  - at: "2026-10-19T12:03:25Z"
    level: L2
    summary: added coverage for MapSVG (<= 8.16.1)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-111406
---

CVE-2026-111398 describes an improper limitation of a pathname to a restricted directory, commonly referred to as a path traversal vulnerability, affecting the MapSVG plugin (specifically the mapsvg-lite-interactive-vector-maps component) developed by PT Norther Lights Production. This vulnerability impacts all versions of the plugin up to and including 8.16.1. The flaw allows remote, unauthenticated attackers to manipulate file path parameters in HTTP requests, enabling access to files outside of the intended web root directory. If successful, this can lead to the exposure of sensitive configuration files, source code, or other system information, significantly increasing the risk of further exploitation or complete server compromise.

## Impact

The vulnerability poses a high risk to web servers running vulnerable versions of the MapSVG plugin, as it facilitates unauthorized information disclosure. Depending on the server configuration and file permissions, an attacker could extract credentials, environment variables, or database connection strings, potentially leading to escalation of privilege and full system takeover.

## Recommendation

1. Inventory all web application assets to identify instances of the MapSVG plugin.
2. Upgrade the MapSVG plugin to the latest version, ensuring it is beyond the affected range (8.16.1).
3. If an immediate upgrade is not feasible, implement a Web Application Firewall (WAF) rule to block incoming HTTP requests containing directory traversal sequences (e.g., ../, ..\).
4. Perform a security review of web server file permissions to ensure the web service account has the principle of least privilege, minimizing the impact of potential file disclosure.
