---
title: SQL Injection in SiYuan fullTextSearchAssetContent Endpoint
slug: 2026-08-siyuan-sqli
description: SiYuan versions before 3.7.3 contain a critical SQL injection vulnerability in the fullTextSearchAssetContent endpoint, allowing unauthenticated attackers to execute arbitrary SQL commands on the backend asset-content database.
date: "2026-08-03T16:04:30Z"
lastmod: "2026-08-03T16:05:53Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - sql-injection
  - web-vulnerability
vendors:
  - siyuan-note
products:
  - SiYuan (< 3.7.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: SiYuan versions before v3.7.3 contain SQL injection vulnerabilities in the fullTextSearchAssetContent endpoint reachable by unauthenticated users.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: Anonymous readers or publish RoleReader tokens can supply a heading block ID to read full rendered content of publish-disabled documents that should be restricted.
    confidence_band: high
cves:
  - id: CVE-2026-69083
    cvss: 10
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-69083
  - https://github.com/siyuan-note/siyuan/security/advisories/GHSA-fph3-ghq9-vw66
  - https://www.vulncheck.com/advisories/siyuan-before-sql-injection-via-fulltextsearchassetcontent
  - https://nvd.nist.gov/vuln/detail/CVE-2026-68587
  - https://github.com/siyuan-note/siyuan/security/advisories/GHSA-69mh-gvh4-8gp7
rules:
  - title: Detect CVE-2026-69083 Exploitation - SQL Injection in fullTextSearchAssetContent
    description: Detects potential exploitation of CVE-2026-69083 where an unauthenticated user sends a request to the fullTextSearchAssetContent endpoint containing suspicious SQL injection patterns.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-68587 Exploitation - Unauthorized Access to SiYuan Heading Endpoints
    description: Detects potential exploitation attempts of CVE-2026-68587 by monitoring for unauthorized access to sensitive heading transaction endpoints in SiYuan.
    platform: sigma
    severity: high
    tactics:
      - collection
    techniques:
      - T1592
    data_sources:
      - webserver
rules_count: 2
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade SiYuan to version 3.7.3 or later
      owner: IT Operations
      due: 24h
      evidence: Vendor advisory GHSA-fph3-ghq9-vw66
  mitigation_plan:
    - priority: immediate
      action: Restrict external access to the fullTextSearchAssetContent endpoint
      owner: IT Operations
      addresses: CVE-2026-69083
      evidence: Vulnerability reachable by unauthenticated users
updates:
  - at: "2026-08-03T16:05:53Z"
    level: L2
    summary: 'added detection rule: Detect CVE-2026-68587 Exploitation - Unauthorized Access to SiYuan Heading Endpoints'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-68587
---

SiYuan versions prior to 3.7.3 are vulnerable to an unauthenticated SQL injection vulnerability located in the fullTextSearchAssetContent endpoint. The vulnerability is caused by improper neutralization of special elements in input parameters, specifically when processing REGEXP clauses. An unauthenticated attacker can exploit this flaw to execute arbitrary SQL commands against the read-write asset-content database. This allows for unauthorized reading, modification, or deletion of stored notebook data. The vulnerability is considered high-risk due to the lack of required authentication and the potential for full data compromise within the application environment.

## Impact

Successful exploitation allows unauthenticated attackers to perform unauthorized operations on the SiYuan database. This can result in complete loss of confidentiality and integrity for user data stored within notebooks, including the potential for mass data deletion or unauthorized exfiltration of sensitive information across all notebooks managed by the instance.

## Recommendation

1. Upgrade all SiYuan installations to version 3.7.3 or later immediately to resolve the vulnerability documented in CVE-2026-69083.
2. Implement strict ingress filtering for the application, specifically restricting access to the fullTextSearchAssetContent API endpoint from untrusted networks.
3. Review webserver logs for requests to the fullTextSearchAssetContent endpoint containing SQL injection markers, such as unexpected use of semicolon, comments, or REGEXP keywords in query parameters.
