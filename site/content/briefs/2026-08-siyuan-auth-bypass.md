---
title: Information Disclosure Vulnerability in SiYuan
slug: 2026-08-siyuan-auth-bypass
description: SiYuan versions before 3.7.4 are vulnerable to unauthorized information disclosure via the renderAttributeView component, allowing unauthenticated attackers to access restricted database content.
date: "2026-08-12T22:52:07Z"
lastmod: "2026-09-05T00:08:16Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:siyuan_note:siyuan:*:*:*:*:*:*:*:*
has_poc: true
tags:
  - vulnerability
  - information-disclosure
  - authorization-bypass
  - privilege-escalation
  - command-injection
  - windows
  - path-traversal
  - file-deletion
vendors:
  - siyuan-note
products:
  - siyuan (< 3.7.4)
  - SiYuan (< 3.7.4)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: SiYuan versions before v3.7.4 fail to properly filter related-database content in renderAttributeView, allowing anonymous readers to access Relation and Rollup cell contents
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: Attackers can establish a WebSocket connection to the publish surface and passively receive real-time content events including password-protected and forbidden documents without authentication.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers can inject malicious payloads through the setAttrViewColWidth API that break out of style attributes and inject event handlers on every table cell, executing arbitrary code in the Electron renderer with Node integration enabled.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers can... trigger the Microsoft Defender exclusion flow to execute arbitrary commands with administrator privileges.
    confidence_band: high
cves:
  - id: CVE-2026-72798
    cvss: 8.6
    epss: 0.00256
  - id: CVE-2026-72810
    cvss: 8.6
    epss: 0.00313
  - id: CVE-2026-73044
    cvss: 9
    epss: 0.00247
  - id: CVE-2026-74801
    cvss: 8.2
    epss: 0.00265
  - id: CVE-2026-60084
    cvss: 8.7
    epss: 0.00346
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-72798
  - https://github.com/siyuan-note/siyuan/security/advisories/GHSA-mfrj-v65r-979c
  - https://www.vulncheck.com/advisories/siyuan-before-information-disclosure-via-renderattributeview
  - https://nvd.nist.gov/vuln/detail/CVE-2026-72810
  - https://github.com/siyuan-note/siyuan/security/advisories/GHSA-mw8r-mw84-88v2
  - https://www.vulncheck.com/advisories/siyuan-before-publish-boundary-bypass-via-websocket
  - https://nvd.nist.gov/vuln/detail/CVE-2026-73044
  - https://github.com/siyuan-note/siyuan/security/advisories/GHSA-rj55-w3xr-gj62
  - https://www.vulncheck.com/advisories/siyuan-before-stored-cross-site-scripting-via-column-width
  - https://nvd.nist.gov/vuln/detail/CVE-2026-74801
  - https://github.com/siyuan-note/siyuan/security/advisories/GHSA-vmp7-pm7g-ghcc
  - https://nvd.nist.gov/vuln/detail/CVE-2026-60084
  - https://github.com/siyuan-note/siyuan/security/advisories/GHSA-w938-w7m4-qrj8
  - https://www.vulncheck.com/advisories/siyuan-before-arbitrary-file-deletion-via-removetemplate
  - https://github.com/advisories/GHSA-mfrj-v65r-979c
rules:
  - title: Detects CVE-2026-74801 Exploitation - Suspicious Elevator.exe Arguments
    description: Detects exploitation of CVE-2026-74801 by monitoring the command line of elevator.exe for shell metacharacters indicative of command injection.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1059.003
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Patch SiYuan to version 3.7.4
      owner: IT Operations
      due: 24h
      evidence: Vendor security advisory and NVD entry mandate update to 3.7.4
updates:
  - at: "2026-08-14T14:12:03Z"
    level: L2
    summary: added coverage for SiYuan
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-72810
  - at: "2026-08-15T22:20:59Z"
    level: L2
    summary: added coverage for SiYuan (< 3.7.4)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-73044
  - at: "2026-08-17T12:48:04Z"
    level: L2
    summary: 'added detection rule: Detects CVE-2026-74801 Exploitation - Suspicious Elevator.exe Arguments'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-74801
  - at: "2026-08-22T13:30:57Z"
    level: L2
    summary: added coverage for SiYuan
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-60084
  - at: "2026-09-05T00:08:16Z"
    level: L2
    summary: poc_available; added CVE-2026-60084 +3
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-mfrj-v65r-979c
---

SiYuan versions prior to 3.7.4 contain a critical security vulnerability (CVE-2026-72798) involving improper authorization checks within the renderAttributeView component. This flaw allows anonymous, unauthenticated users to access sensitive information contained in Relation and Rollup cells that are supposed to be hidden or password-protected.

An attacker can exploit this by requesting published databases that have relationships with restricted databases, forcing the application to disclose content that should remain inaccessible. Additionally, the vulnerability allows for the bypass of row-level filtering if the first column of the database is a non-block type. This exposes organizations relying on SiYuan for internal documentation or data management to potential data breaches if their instances are internet-facing. Defenders should prioritize updating to version 3.7.4 or higher to remediate this issue.

## Attack Chain

1. Attacker identifies an internet-exposed instance of SiYuan running a version prior to 3.7.4.
2. Attacker discovers or enumerates a publicly accessible (published) database within the SiYuan instance.
3. Attacker identifies relationships (links or rollups) between the published database and a target sensitive or password-protected database.
4. Attacker crafts a request targeting the renderAttributeView component to retrieve attribute views of the published database.
5. The application fails to validate authorization for the related sensitive database entries during the rendering process.
6. The backend processes the request and returns the sensitive content from the restricted database in the response.
7. Attacker parses the response to exfiltrate Relation or Rollup cell data.

## Impact

Successful exploitation allows unauthenticated attackers to view sensitive, password-protected, or hidden data stored within SiYuan databases. This could lead to the unauthorized exposure of proprietary information, PII, or internal organizational documentation. The vulnerability is considered high-risk due to the ease of reachability and lack of authentication required for exploitation.

## Recommendation

* Upgrade all instances of SiYuan to version 3.7.4 or later immediately.
* Restrict access to SiYuan instances by placing them behind a VPN or an authenticated reverse proxy to limit exposure to unauthenticated external requests.
* Audit logs for suspicious access patterns to the renderAttributeView endpoint or unusual spikes in data retrieval requests.
