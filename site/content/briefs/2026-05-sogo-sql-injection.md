---
title: 'CVE-2026-8851: SOGo SQL Injection Vulnerability in ACL Management'
slug: 2026-05-sogo-sql-injection
description: SOGo 5.12.7 is vulnerable to SQL injection in the Access Control List management functionality, allowing authenticated users to extract arbitrary data from the database by injecting SQL subqueries through the uid parameter of the addUserInAcls endpoint, which can be exfiltrated via the /acls API.
date: "2026-05-18T21:18:45Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - sql-injection
  - cve-2026-8851
  - data-exfiltration
vendors:
  - SOGo
products:
  - SOGo 5.12.7
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
cves:
  - id: CVE-2026-8851
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-8851
rules:
  - title: Detect SOGo addUserInAcls SQL Injection
    description: Detects SQL injection attempts in the addUserInAcls endpoint by looking for SQL syntax in the uid parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect SOGo Data Exfiltration via acls API
    description: Detects potential data exfiltration by monitoring requests to the `/acls` endpoint after detecting SQL injection attempts in addUserInAcls
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1041
    data_sources:
      - webserver
rules_count: 2
---

SOGo version 5.12.7 is susceptible to a SQL injection vulnerability within its Access Control List (ACL) management feature. Authenticated users can exploit this flaw by injecting malicious SQL subqueries via the `uid` parameter in the `addUserInAcls` endpoint. Successful exploitation allows attackers to extract arbitrary data from the database. The injected SQL code can be crafted to write the extracted data into the `sogo_acl` table. Attackers can then retrieve this data through the `/acls` API, effectively creating an out-of-band data exfiltration channel. This vulnerability, identified as CVE-2026-8851, poses a significant risk to organizations using vulnerable versions of SOGo.

## Attack Chain

1. An attacker authenticates to the SOGo application.
2. The attacker crafts a malicious HTTP request to the `addUserInAcls` endpoint.
3. The request includes a SQL injection payload within the `uid` parameter.
4. The SOGo application processes the request without proper sanitization, executing the injected SQL code.
5. The injected SQL code extracts sensitive data from the database and writes it into the `sogo_acl` table.
6. The attacker sends a request to the `/acls` API endpoint.
7. The SOGo application retrieves the data from the `sogo_acl` table.
8. The attacker receives the extracted data, achieving out-of-band data exfiltration.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2026-8851) allows attackers to extract arbitrary data from the SOGo database. This could include sensitive user information, credentials, and other confidential data. The CVSS v3.1 base score is 8.1, reflecting the high potential for data breach and compromise of the SOGo application and its underlying database.

## Recommendation

*   Upgrade SOGo to a patched version beyond 5.12.7 to remediate CVE-2026-8851.
*   Deploy the Sigma rule `Detect SOGo addUserInAcls SQL Injection` to detect potential exploitation attempts against the `addUserInAcls` endpoint.
*   Monitor web server logs for suspicious requests to the `/acls` API after unusual activity on the `addUserInAcls` endpoint, as this is the exfiltration point.
*   Implement input validation and sanitization on the `uid` parameter of the `addUserInAcls` endpoint if patching is not immediately feasible.
