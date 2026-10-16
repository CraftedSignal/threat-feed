---
title: Insecure Direct Object Reference in Shaiwz data-platform-open
slug: 2026-10-idor-shaiwz
description: An IDOR vulnerability in Shaiwz data-platform-open allows authenticated users to access, enumerate, and modify foreign workspace datasources by manipulating numeric IDs in API requests.
date: "2026-10-16T18:50:30Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:shaiwz:data-platform-open:*:*:*:*:*:*:*:*
tags:
  - idor
  - api-security
  - web-application
  - cve-2026-111695
vendors:
  - Shaiwz
products:
  - data-platform-open (<= efeacd3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: Attackers can send foreign sequential ids to /datasource/detail, /listSchemaTable, /tableDetail, /update or /delete to obtain JDBC credentials, enumerate database schemas, and modify or delete datasources.
    confidence_band: high
cves:
  - id: CVE-2026-111695
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111695
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade Shaiwz data-platform-open past commit efeacd3 to remediate CVE-2026-111695
      owner: IT Operations
      due: 72h
      evidence: NVD vulnerability disclosure
  hunt_leads:
    - lead: Identify accounts making requests to /datasource/detail or /tableDetail with numeric IDs inconsistent with their assigned workspace
      technique_id: T1592
      data_needed:
        - webserver access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: NVD summary of vulnerable endpoints
  mitigation_plan:
    - priority: immediate
      action: Upgrade to a version post-dating commit efeacd3
      owner: IT Operations
      addresses: CVE-2026-111695
      evidence: NVD report
---

Shaiwz data-platform-open, up to and including commit efeacd3, is susceptible to an Insecure Direct Object Reference (IDOR) vulnerability (CVE-2026-111695). The application fails to properly validate the authorization of authenticated workspace members when interacting with datasource-related API endpoints. An attacker can manipulate numeric identifiers within API requests to perform unauthorized actions on datasources belonging to other workspaces. This flaw enables attackers to exfiltrate sensitive JDBC credentials, enumerate database schemas, and perform destructive actions, such as modifying or deleting datasource configurations. This vulnerability poses a significant risk to data confidentiality and integrity within multi-tenant environments where the platform is deployed.

## Impact

Successful exploitation allows authenticated attackers to gain unauthorized access to cross-tenant data. Potential damage includes the theft of sensitive JDBC connection strings and database credentials, mapping of internal database structures, and unauthorized alteration or deletion of datasource configurations. This can lead to total loss of datasource integrity and potential lateral movement into backend database infrastructure.

## Recommendation

Prioritized, concrete actions for security teams:

* Apply the security patch for CVE-2026-111695 once provided by the vendor, or upgrade the application beyond commit efeacd3 immediately.
* Monitor web server access logs for anomalous patterns of sequential or high-volume requests to the endpoints /datasource/detail, /listSchemaTable, /tableDetail, /update, and /delete, particularly those associated with authenticated user sessions that deviate from normal usage patterns.
* Audit access control logs to identify users attempting to access resource IDs not assigned to their specific workspace.
