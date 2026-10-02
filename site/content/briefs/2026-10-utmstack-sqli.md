---
title: SQL Injection in UTMStack via UtmAssetGroupService
slug: 2026-10-utmstack-sqli
description: UTMStack versions prior to 11.2.16 are vulnerable to an authenticated SQL injection in the UtmAssetGroupService, allowing attackers to execute arbitrary commands with DBA privileges.
date: "2026-10-02T20:27:13Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:utmstack:utmstack:*:*:*:*:*:*:*:*
tags:
  - sql-injection
  - vulnerability
  - web-application
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
cves:
  - id: CVE-2026-82039
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82039
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
---

UTMStack versions prior to 11.2.16 contain a critical SQL injection vulnerability located within the UtmAssetGroupService.searchQueryBuilder() method. This vulnerability arises due to the unsanitized concatenation of user-supplied input into native PostgreSQL queries via String.format(). Specifically, an authenticated attacker can target the GET /api/utm-asset-groups/searchGroupsByFilter endpoint, passing malicious payloads through the assetType and groupName parameters. Because the application interacts with the backend database using DBA-level privileges, successful exploitation grants the attacker full access to the database, including the ability to read, modify, or delete sensitive data, and potentially escalate to filesystem access on the hosting server.

## Impact

Successful exploitation of this vulnerability allows an authenticated attacker to compromise the integrity and confidentiality of the UTMStack database. Given the elevated DBA privileges of the application, this vulnerability provides a vector for complete data exfiltration, unauthorized administrative actions, and potential remote code execution via database-linked filesystem commands.

## Recommendation

Upgrade all instances of UTMStack to version 11.2.16 or later immediately. Access logs should be audited for anomalous activity targeting the /api/utm-asset-groups/searchGroupsByFilter endpoint, particularly requests containing SQL control characters or keywords (e.g., UNION, SELECT, OR, 1=1) within the assetType or groupName parameters.
