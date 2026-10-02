---
title: SQL Injection in UTMStack via UtmAssetGroupService
slug: 2026-10-utmstack-sqli
description: UTMStack versions prior to 11.2.16 are vulnerable to an authenticated SQL injection in the UtmAssetGroupService, allowing attackers to execute arbitrary commands with DBA privileges.
date: "2026-10-02T20:27:13Z"
lastmod: "2026-10-02T22:27:31Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:utmstack:utmstack:*:*:*:*:*:*:*:*
tags:
  - sql-injection
  - vulnerability
  - web-application
  - remote-code-execution
  - cve-2026-82041
  - ssrf
  - internal-reconnaissance
vendors:
  - UTMStack
products:
  - UTMStack (< 11.2.16)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: UTMStack before 11.2.16 contains a SQL injection vulnerability in UtmAssetGroupService.searchQueryBuilder() that allows authenticated attackers to inject arbitrary SQL
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Any authenticated user, regardless of role, can send arbitrary operating-system commands over gRPC to any connected agent, resulting in command execution on monitored endpoints.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: resulting in command execution on monitored endpoints where agent processes commonly run as root or SYSTEM.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1199
    technique_name: Trusted Relationship
    evidence: The vulnerability allows attackers to gain full administrative API access by presenting a valid Utm-Internal-Key header.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552.003
    technique_name: 'Unsecured Credentials: Credentials in Environment Variables'
    evidence: The internal key is stored in the INTERNAL_KEY environment variable.
    confidence_band: high
cves:
  - id: CVE-2026-82039
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82039
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82041
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82042
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82044
rules:
  - title: Detect Unauthorized Access via Utm-Internal-Key
    description: Detects potential exploitation of CVE-2026-82042 by monitoring for the presence of the 'Utm-Internal-Key' header in HTTP requests, which should generally not be present in legitimate client-facing traffic.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1199
    data_sources:
      - webserver
  - title: Detect CVE-2026-82044 Exploitation - SSRF via PdfService
    description: Detects exploitation attempts against the /api/generate-pdf-report endpoint where the URL parameter attempts to access internal infrastructure.
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
    - SOC
  immediate_actions:
    - action: Upgrade UTMStack to version 11.2.16 or later
      owner: IT Operations
      due: 24h
      evidence: NVD vulnerability disclosure
  hunt_leads:
    - lead: Audit web access logs for GET requests to /api/utm-asset-groups/searchGroupsByFilter containing SQL syntax
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Endpoint identified in vulnerability disclosure
  mitigation_plan:
    - priority: immediate
      action: Upgrade to 11.2.16
      owner: IT Operations
      addresses: CVE-2026-82039
      evidence: NVD vulnerability disclosure
updates:
  - at: "2026-10-02T22:27:06Z"
    level: L2
    summary: added coverage for UTMStack (< 11.2.16)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-82041
  - at: "2026-10-02T22:27:16Z"
    level: L2
    summary: 'added detection rule: Detect Unauthorized Access via Utm-Internal-Key'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-82042
  - at: "2026-10-02T22:27:31Z"
    level: L2
    summary: 'added detection rule: Detect CVE-2026-82044 Exploitation - SSRF via PdfService'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-82044
---

UTMStack versions prior to 11.2.16 contain a critical SQL injection vulnerability located within the UtmAssetGroupService.searchQueryBuilder() method. This vulnerability arises due to the unsanitized concatenation of user-supplied input into native PostgreSQL queries via String.format(). Specifically, an authenticated attacker can target the GET /api/utm-asset-groups/searchGroupsByFilter endpoint, passing malicious payloads through the assetType and groupName parameters. Because the application interacts with the backend database using DBA-level privileges, successful exploitation grants the attacker full access to the database, including the ability to read, modify, or delete sensitive data, and potentially escalate to filesystem access on the hosting server.

## Impact

Successful exploitation of this vulnerability allows an authenticated attacker to compromise the integrity and confidentiality of the UTMStack database. Given the elevated DBA privileges of the application, this vulnerability provides a vector for complete data exfiltration, unauthorized administrative actions, and potential remote code execution via database-linked filesystem commands.

## Recommendation

Upgrade all instances of UTMStack to version 11.2.16 or later immediately. Access logs should be audited for anomalous activity targeting the /api/utm-asset-groups/searchGroupsByFilter endpoint, particularly requests containing SQL control characters or keywords (e.g., UNION, SELECT, OR, 1=1) within the assetType or groupName parameters.
