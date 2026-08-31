---
title: ToolJet Database Privilege Escalation in join_tables Endpoint
slug: 2026-08-tooljet-privesc
description: ToolJet Database versions prior to 3.16.44 contain a privilege escalation vulnerability in the join_tables endpoint that permits unauthenticated access to arbitrary tables across workspaces.
date: "2026-08-31T11:18:13Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:tooljet:database:*:*:*:*:*:*:*:*
vendors:
  - ToolJet
products:
  - ToolJet Database (< 3.16.44)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: ToolJet Database versions before v3.16.44 contain a privilege escalation vulnerability in the join_tables endpoint that grants JOIN_TABLES ability to all authenticated users without role or workspace membership validation.
    confidence_band: high
cves:
  - id: CVE-2026-82869
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82869
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade ToolJet Database to version 3.16.44 or later
      owner: IT Operations
      addresses: CVE-2026-82869
      evidence: CVE-2026-82869 vulnerability report
---

ToolJet Database versions before v3.16.44 contain a privilege escalation vulnerability within the join_tables endpoint. This flaw allows any authenticated user to perform unauthorized read operations on tables belonging to workspaces they do not belong to or have permissions for. The root cause is a failure in the application logic to validate workspace membership or user role permissions when a request is made to the join_tables interface. By manipulating workspace identifiers within the request path, an attacker can enumerate and exfiltrate data from arbitrary tables across the entire application instance. This issue presents a significant data confidentiality risk, particularly in multi-tenant or collaborative enterprise environments where strict isolation between workspace data is expected.

## Impact

Successful exploitation of this vulnerability enables authenticated users to bypass workspace-level access controls and read sensitive information from any database table managed by the ToolJet instance. This could lead to massive unauthorized data exfiltration in multi-tenant environments.

## Recommendation

Upgrade all ToolJet Database installations to version 3.16.44 or later immediately. Access logs should be audited for anomalous HTTP requests to the join_tables endpoint where the workspace identifier in the path deviates from the user's authorized workspace context.
