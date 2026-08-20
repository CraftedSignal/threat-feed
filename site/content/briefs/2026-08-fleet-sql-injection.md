---
title: SQL Injection in Fleet Premium Okta Integration
slug: 2026-08-fleet-sql-injection
description: A SQL injection vulnerability in the Fleet Premium Okta conditional access integration allows an enrolled host to execute arbitrary database queries, leading to privilege escalation and potential remote code execution.
date: "2026-08-20T19:13:22Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Fleet
products:
  - Fleet Premium (< 4.86.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A SQL injection vulnerability in Fleet's Okta conditional access integration could allow an attacker who controls a single enrolled host to read or modify arbitrary data in the Fleet database.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-7q96-f8xw-jv5j
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade Fleet Premium to 4.86.2 or disable Okta conditional access integration
      owner: IT Operations
      due: 24h
      evidence: Source identifies upgrade and integration disabling as primary mitigations for CVE-2026-54245
  mitigation_plan:
    - priority: immediate
      action: Upgrade Fleet Premium to 4.86.2
      owner: IT Operations
      addresses: CVE-2026-54245
      evidence: Source advisory recommends this as the fix
---

Fleet Premium versions prior to 4.86.2 contain a critical SQL injection vulnerability (CVE-2026-54245) within the Okta conditional access integration. The vulnerability arises because a host-supplied value, reported by the osquery agent during the conditional access check, is processed by the database query without sufficient parameterization or sanitization. Because an attacker who controls a single enrolled host can manipulate the data reported by that agent, they can inject malicious SQL commands. This flaw allows an attacker to query or modify the Fleet database, enabling the extraction of global administrator session tokens. Once a session token is retrieved, an attacker can impersonate a global administrator and leverage the product's administrative features to deploy malicious scripts to any enrolled host, effectively achieving remote code execution across the managed environment.

## Impact

The vulnerability affects organizations utilizing Fleet Premium with the Okta conditional access integration enabled. Successful exploitation poses a high risk to the confidentiality and integrity of the Fleet management database and the availability and security of all enrolled endpoints. Attackers can gain global administrator privileges, which facilitates unauthorized access to sensitive host data, execution of arbitrary commands via osquery, and long-term persistence within the managed fleet infrastructure.

## Recommendation

* Upgrade all instances of Fleet Premium to version 4.86.2 or higher immediately to patch CVE-2026-54245.
* If upgrading is not immediately possible, disable the Okta conditional access integration in the Fleet configuration until the environment can be updated.
* Audit administrative session logs and system logs for unusual queries or unauthorized global administrator activity coinciding with known enrolments.
