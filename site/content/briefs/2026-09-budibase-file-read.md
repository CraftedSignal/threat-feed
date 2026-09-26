---
title: Arbitrary File Read in Budibase OpenAPI Import Validator
slug: 2026-09-budibase-file-read
description: Budibase versions prior to 3.45.0 contain an arbitrary file read vulnerability caused by enabled external JSON reference resolution during OpenAPI/Swagger file imports.
date: "2026-09-26T15:10:36Z"
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
vendors:
  - Budibase
products:
  - Budibase (< 3.45.0)
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
cves:
  - id: CVE-2026-100680
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100680
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
---

Budibase versions prior to 3.45.0 suffer from an arbitrary file read vulnerability located in the OpenAPI/Swagger import validation functionality. The issue arises because the application fails to restrict external JSON reference resolution during the import process. An attacker possessing authenticated access as a builder can exploit this misconfiguration by submitting a crafted OpenAPI specification file containing malicious file:// URI references. 

When the application processes the imported specification, the underlying JSON parser attempts to resolve these external references against the host filesystem. This enables an attacker to read sensitive local files, such as environment variables, which often contain critical secrets like JWT signing keys, database credentials, and third-party API keys. Successful exploitation leads to significant security impact, including potential full system compromise, escalation of privilege, or unauthorized data access, given the sensitivity of configuration data stored in environment files.
