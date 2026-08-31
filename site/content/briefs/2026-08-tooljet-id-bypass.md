---
title: ToolJet Multi-Tenancy Broken Access Control
slug: 2026-08-tooljet-id-bypass
description: ToolJet versions prior to 3.16.208 are vulnerable to broken access control, allowing authenticated builder-role users to perform unauthorized database operations across tenant boundaries.
date: "2026-08-31T11:17:20Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:tooljet:tooljet:*:*:*:*:*:*:*:*
tags:
  - webserver
  - broken-access-control
  - vulnerability
vendors:
  - ToolJet
products:
  - ToolJet (< 3.16.208)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: ToolJet before v3.16.208 fails to validate organizationId ownership in database write and destroy routes, allowing any builder-role user to create, alter, or drop tables in other organizations' databases.
    confidence_band: high
cves:
  - id: CVE-2026-82870
    cvss: 9.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82870
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade ToolJet to 3.16.208 or later
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-82870 fix requirement
  mitigation_plan:
    - priority: immediate
      action: Upgrade ToolJet to 3.16.208 or later
      owner: IT Operations
      addresses: CVE-2026-82870
      evidence: NVD vulnerability remediation
---

ToolJet versions before 3.16.208 contain a critical vulnerability in its multi-tenancy implementation related to the validation of organization ownership. The application fails to properly verify the 'organizationId' during database write and destroy operations. This oversight allows a user assigned the 'builder' role within one organization to interact with, modify, or destroy database tables belonging to different organizations hosted on the same instance. This vulnerability poses a severe risk to data integrity and availability in shared multi-tenant deployments, as it permits unauthorized schema manipulation, arbitrary data insertion, and permanent deletion of tenant data across organization boundaries. Defenders should prioritize patching instances to version 3.16.208 or later to enforce tenant isolation.

## Impact

Successful exploitation allows for cross-tenant data exfiltration, unauthorized modification of sensitive business data, and permanent loss of database tables. This vulnerability is particularly impactful for organizations hosting multiple internal teams or clients on a single shared ToolJet instance, as it undermines the fundamental multi-tenancy security model.

## Recommendation

- Upgrade all ToolJet deployments to version 3.16.208 or later immediately to patch CVE-2026-82870.
- Review application access logs for any database-related API requests involving IDs belonging to organizations outside of the user's assigned scope.
- Audit the list of users currently assigned the 'builder' role and restrict access to strictly verified users until the patch is applied.
