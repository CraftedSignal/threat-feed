---
title: SQL Injection Vulnerability in NocoBase plugin-collection-sql
slug: 2026-10-nocobase-sql-injection
description: An SQL injection vulnerability in NocoBase plugin-collection-sql allows authenticated privileged users to bypass validation and execute arbitrary SQL commands on the underlying PostgreSQL database.
date: "2026-10-19T18:10:01Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:nocobase:plugin-collection-sql:*:*:*:*:*:*:*:*
tags:
  - sql-injection
  - vulnerability
  - web-application
vendors:
  - NocoBase
products:
  - plugin-collection-sql (<= 2.2.28)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: NocoBase @nocobase/plugin-collection-sql through 2.2.28 contains an SQL injection vulnerability that allows privileged users to store unvalidated SQL by bypassing checkSQL() through the sqlCollection:setFields action.
    confidence_band: high
cves:
  - id: CVE-2026-112306
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-112306
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade NocoBase plugin-collection-sql beyond version 2.2.28
      owner: IT Operations
      due: 24h
      evidence: NVD CVE-2026-112306 advisory
  mitigation_plan:
    - priority: immediate
      action: Upgrade affected plugin version
      owner: IT Operations
      addresses: CVE-2026-112306
      evidence: NVD vulnerability record
---

NocoBase plugin-collection-sql through version 2.2.28 contains a critical SQL injection vulnerability identified as CVE-2026-112306. The issue resides in the sqlCollection:setFields action, where the application fails to properly validate user-supplied input before executing it against the database. An authenticated user with sufficient privileges can bypass the checkSQL() validation function to store malicious SQL payloads within the collection configuration. When the collection is subsequently reloaded by the application, the injected statements are executed with the database service account permissions. This allows an attacker to interact with the PostgreSQL backend, enabling unauthorized access to sensitive data, such as pg_shadow password hashes, or the ability to invoke functions like pg_read_file to exfiltrate arbitrary files from the server filesystem. This vulnerability poses a high risk to data confidentiality and integrity.

## Impact

Successful exploitation allows authenticated attackers to perform unauthorized database operations, including data extraction, credential theft, and potentially remote file reading from the server hosting the PostgreSQL database. This compromises the entire data layer and could lead to full system compromise depending on the database service account privileges and server configuration.

## Recommendation

- Upgrade NocoBase plugin-collection-sql to a patched version beyond 2.2.28 immediately.
- Review all database collection configurations in NocoBase for unauthorized or unexpected modifications to field definitions.
- Restrict administrative or privileged access to the NocoBase instance to only trusted users to mitigate the risk of malicious exploitation of this feature.
- Implement strict database permission controls, ensuring the PostgreSQL service account operates with the principle of least privilege, specifically restricting access to system tables and sensitive filesystem functions.
