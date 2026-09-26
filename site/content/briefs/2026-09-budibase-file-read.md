---
title: Arbitrary File Read in Budibase OpenAPI Import Validator
slug: 2026-09-budibase-file-read
description: Budibase versions prior to 3.45.0 contain an arbitrary file read vulnerability caused by enabled external JSON reference resolution during OpenAPI/Swagger file imports.
date: "2026-09-26T15:10:36Z"
lastmod: "2026-09-26T15:12:15Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:budibase:budibase:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - web-application
  - data-exfiltration
  - sql-injection
  - cve
  - authentication-bypass
  - sso
  - identity-management
  - idor
  - broken-access-control
  - web-security
vendors:
  - Budibase
products:
  - Budibase (< 3.45.0)
  - Budibase (3.41.0 - 3.44.x)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Budibase versions before 3.45.0 fail to disable external JSON reference resolution in the OpenAPI/Swagger import validator, allowing authenticated builders to read arbitrary local files.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1005
    technique_name: Data from Local System
    evidence: Attackers with builder access can embed file:// references in OpenAPI specifications submitted to the import endpoint to exfiltrate sensitive files
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.001
    technique_name: PowerShell
    evidence: 'Because the MySQL connection is opened with multipleStatements: true, stacked statements run as Budibase''s datasource user.'
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1550.001
    technique_name: Use Alternate Authentication Material
    evidence: An attacker who can register at an IdP that the tenant trusts for OIDC and assert a victim's invited email address claims the pending invite.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1550.001
    technique_name: Use Alternate Authentication Material
    evidence: The attacker inherits all of its granted privileges, including builder and admin.global, with no admin exclusion.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: The endpoint fails to properly scope data by workspace, allowing authenticated users with builder privileges to perform an insecure direct object reference (IDOR) to enumerate chat identity link records.
    confidence_band: high
cves:
  - id: CVE-2026-100680
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100680
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100683
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100684
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100685
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Budibase to version 3.45.0 or later.
      owner: IT Operations
      due: 48h
      evidence: Source states Budibase versions before 3.45.0 are affected.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Budibase to 3.45.0.
      owner: IT Operations
      addresses: CVE-2026-100680
      evidence: NVD advisory for CVE-2026-100680.
updates:
  - at: "2026-09-26T15:12:01Z"
    level: L2
    summary: added coverage for Budibase (< 3.45.0)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-100683
  - at: "2026-09-26T15:12:08Z"
    level: L2
    summary: added coverage for Budibase (3.41.0 - 3.44.x)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-100684
  - at: "2026-09-26T15:12:15Z"
    level: L2
    summary: added coverage for Budibase (< 3.45.0)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-100685
---

Budibase versions prior to 3.45.0 suffer from an arbitrary file read vulnerability located in the OpenAPI/Swagger import validation functionality. The issue arises because the application fails to restrict external JSON reference resolution during the import process. An attacker possessing authenticated access as a builder can exploit this misconfiguration by submitting a crafted OpenAPI specification file containing malicious file:// URI references. 

When the application processes the imported specification, the underlying JSON parser attempts to resolve these external references against the host filesystem. This enables an attacker to read sensitive local files, such as environment variables, which often contain critical secrets like JWT signing keys, database credentials, and third-party API keys. Successful exploitation leads to significant security impact, including potential full system compromise, escalation of privilege, or unauthorized data access, given the sensitivity of configuration data stored in environment files.
