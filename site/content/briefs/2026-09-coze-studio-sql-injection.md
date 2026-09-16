---
title: Insufficient Validation in Coze Studio Workflow SQL Nodes
slug: 2026-09-coze-studio-sql-injection
description: Coze Studio versions up to 0.5.1 contain an input validation vulnerability in workflow SQL customization nodes allowing authenticated attackers to bypass workspace isolation and execute unauthorized SQL queries.
date: "2026-09-16T21:57:02Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:bytedance:coze_studio:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - sql-injection
  - multi-tenancy
  - cve-2026-92788
vendors:
  - ByteDance
products:
  - Coze Studio (<= 0.5.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1505.003
    technique_name: 'Server Software Component: SQL Stored Procedures'
    evidence: Authenticated attackers can enumerate predictable table identifiers and execute SQL statements against other workspaces' memory databases.
    confidence_band: high
cves:
  - id: CVE-2026-92788
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92788
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade Coze Studio to the version following 0.5.1 once the vendor patch is available.
      owner: IT Operations
      addresses: CVE-2026-92788
      evidence: Source identifies vulnerability in versions up to 0.5.1.
---

Coze Studio versions through 0.5.1 are affected by a workspace isolation vulnerability within their workflow SQL customization nodes. The application fails to validate whether the table names provided in these nodes belong to the caller's authorized workspace. Because table identifiers are predictable, an authenticated attacker can manipulate these inputs to target memory databases belonging to other workspaces. This flaw allows for unauthorized read, insert, and delete operations across workspace boundaries. Defenders should note that this requires a user to have access to the Coze Studio environment, making it a critical risk for multi-tenant deployments where users may attempt to escalate privileges or perform cross-workspace data exfiltration.

## Impact

Successful exploitation allows authenticated users to access, modify, or delete sensitive data within memory databases of other workspaces within the same Coze Studio instance. This represents a complete breach of multi-tenancy isolation. The number of impacted organizations is unknown, but any deployment utilizing version 0.5.1 or earlier is at risk.

## Recommendation

- Upgrade Coze Studio to the version following 0.5.1 as soon as it is released to remediate the input validation logic in SQL customization nodes.
- Audit workspace logs for anomalous SQL activity originating from workflow customization nodes where the requested table identifiers do not match the expected workspace scope.
- Implement strict workspace-level access controls to limit the number of users with permissions to create or edit workflow SQL customization nodes.
