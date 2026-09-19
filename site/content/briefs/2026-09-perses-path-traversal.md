---
title: Perses Filesystem Path Traversal Vulnerability
slug: 2026-09-perses-path-traversal
description: The Perses project, when configured with a filesystem database, fails to validate the project parameter in list requests, enabling unauthorized directory traversal and arbitrary file read access.
date: "2026-09-18T19:49:24Z"
lastmod: "2026-09-19T07:44:51Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:perses:perses:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - path-traversal
  - security-misconfiguration
  - authorization-bypass
  - cve-2026-63458
vendors:
  - Perses
products:
  - Perses (< 0.54.0-rc.0)
  - Perses (< 0.54.0-beta.3)
  - perses (>= 0.43.0, < 0.54.0-rc.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Attacker can read arbitrary YAML/JSON files from the server host and can bypass the security constraints to get access to other resources contained in the file database.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A user holding only GlobalDatasource:create can create a GlobalDatasource and attached to it a GlobalSecret without having the right to get access to.
    confidence_band: high
cves:
  - id: CVE-2026-63445
references:
  - https://github.com/advisories/GHSA-vr5f-w35q-98jp
  - https://github.com/advisories/GHSA-cjgj-2fwf-4c2w
  - https://nvd.nist.gov/vuln/detail/CVE-2026-63458
  - https://github.com/advisories/GHSA-4227-9989-jrhx
rules:
  - title: Detect CVE-2026-63445 Exploitation - Path Traversal in Perses List Endpoints
    description: Detects path traversal attempts targeting Perses list endpoints by monitoring for directory traversal characters in the project query parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Team
  immediate_actions:
    - action: Upgrade Perses to v0.54.0-rc.0 or later.
      owner: IT Operations
      due: 48h
      evidence: Source Patches section
  mitigation_plan:
    - priority: immediate
      action: Migrate from filesystem database to SQL database.
      owner: IT Operations
      addresses: CVE-2026-63445
      evidence: Source Workarounds section
updates:
  - at: "2026-09-18T19:50:02Z"
    level: L2
    summary: added coverage for Perses (< 0.54.0-beta.3)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-cjgj-2fwf-4c2w
  - at: "2026-09-19T07:44:51Z"
    level: L2
    summary: added coverage for perses (>= 0.43.0, < 0.54.0-rc.0)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-4227-9989-jrhx
---

Perses, an open-source project, contains a security vulnerability (CVE-2026-63445) involving improper validation of the project parameter in its list API endpoints when utilizing a filesystem database backend. The application binds the user-supplied project value directly from the request into a query structure without sanitizing directory-traversal sequences. 

While validation logic exists for Create and Update operations, it is absent for List operations. Consequently, an unauthenticated attacker can manipulate the project parameter in API requests (e.g., /api/v1/dashboards?project=../) to traverse outside intended directories. This allows the reading of arbitrary YAML or JSON files residing on the host server, potentially exposing sensitive resource configurations and bypassing internal security controls. This vulnerability affects all versions of Perses prior to v0.54.0-rc.0.

## Impact

Successful exploitation allows attackers to gain unauthorized access to arbitrary YAML and JSON files stored on the server host. This information disclosure can lead to the exposure of proprietary configurations and internal resource metadata, undermining the security model of the Perses deployment. Organizations using the filesystem database backend are at high risk, as this configuration is inherently vulnerable to this traversal attack.

## Recommendation

* Upgrade Perses to version 0.54.0-rc.0 or later immediately to patch CVE-2026-63445.
* If upgrading is not immediately feasible, migrate the database backend from the filesystem to an SQL-based database as a workaround.
* Inspect web server and application logs for unusual URL parameters containing directory traversal sequences (e.g., "../") directed at list endpoints such as /api/v1/dashboards.
