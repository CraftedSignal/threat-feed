---
title: Missing Authorization Vulnerability in ArcadeDB DELETE FUNCTION Statement
slug: 2026-08-arcadedb-auth-bypass
description: ArcadeDB versions 26.7.3 and earlier are vulnerable to a missing authorization flaw allowing any authenticated database user to delete server-side functions via the command API.
date: "2026-08-18T12:54:04Z"
lastmod: "2026-08-19T14:35:16Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - privilege-escalation
  - database-security
vendors:
  - ArcadeDB
products:
  - ArcadeDB
  - ArcadeDB (<= 26.7.3)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: Any user with database access can execute DELETE FUNCTION via the command API to permanently remove any registered server-side function.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A user with only database access can add or overwrite SQL or Cypher functions in an existing library and persist the change, enabling tampering with admin-defined function logic.
    confidence_band: high
cves:
  - id: CVE-2026-75846
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75846
  - https://nvd.nist.gov/vuln/detail/CVE-2026-76223
rules:
  - title: Detects CVE-2026-75846 Exploitation - Unauthorized DELETE FUNCTION Execution
    description: Detects unauthorized attempts to execute the DELETE FUNCTION SQL statement via the ArcadeDB command API.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade ArcadeDB to version 26.8.1
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-75846 vulnerability remediation
    - action: Deploy detection rule for DELETE FUNCTION API activity
      owner: Detection Engineering
      due: 24h
      evidence: Source-identified exploit path for CVE-2026-75846
updates:
  - at: "2026-08-19T14:35:16Z"
    level: L2
    summary: added coverage for ArcadeDB (<= 26.7.3)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-76223
---

ArcadeDB versions 26.7.3 and earlier contain a missing authorization vulnerability in the DELETE FUNCTION SQL statement. The underlying issue exists within the DeleteFunctionStatement.executeSimple method, which fails to perform a checkPermissionsOnDatabase(UPDATE_SCHEMA) verification before unregistering and persisting the deletion of a server-side function. This allows any user who has established a connection to the database to execute a DELETE FUNCTION command via the HTTP Command API. By targeting the /api/v1/command/{db} endpoint, an unprivileged user can permanently remove critical server-side functions, including those governing security-relevant logic. This vulnerability (CVE-2026-75846) directly impacts the integrity and availability of the database environment by enabling unauthorized function destruction. Defenders should prioritize patching to version 26.8.1 or later to remediate the missing authorization check.

## Impact

Successful exploitation allows unauthorized users to delete any server-side function within the database. This leads to the destruction of custom application logic, potential disruption of security controls that rely on server-side functions, and general loss of service integrity. There is no requirement for administrative privileges to execute the malicious command, making this a significant risk for multi-tenant or shared-access database environments.

## Recommendation

- Upgrade ArcadeDB installations to version 26.8.1 or later immediately to patch CVE-2026-75846.
- Inspect web server or application proxy logs for POST requests to the /api/v1/command/ endpoint containing 'DELETE FUNCTION' SQL strings.
- Restrict access to the Command API to known, trusted application service accounts using network-level controls or authentication middleware.
