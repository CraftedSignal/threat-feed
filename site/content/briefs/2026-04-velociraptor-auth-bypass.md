---
title: Velociraptor Authentication Bypass via query() Plugin
slug: 2026-04-velociraptor-auth-bypass
description: Velociraptor versions prior to 0.76.3 contain an authentication bypass vulnerability in the query() plugin, allowing authenticated users to access data from other organizations within the Velociraptor deployment, potentially leading to unauthorized data access and privilege escalation.
date: "2026-04-15T18:17:25Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - velociraptor
  - authentication bypass
  - privilege escalation
  - cve-2026-6290
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-6290
    cvss: 8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6290
  - https://docs.velociraptor.app/announcements/advisories/cve-2026-6290/
rules:
  - title: Detect Cross-Organization Query() Plugin Usage
    description: Detects usage of the Velociraptor query() plugin to target different organizations than the user's primary organization.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Velociraptor Notebook VQL Execution Targeting Multiple Orgs
    description: Detects VQL queries executed via Velociraptor notebooks that attempt to access data from multiple organizations, indicative of potential unauthorized data access.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Velociraptor, a powerful open-source endpoint detection and response (EDR) framework, is vulnerable to an authentication bypass issue affecting versions prior to 0.76.3. The vulnerability, identified as CVE-2026-6290, resides within the `query()` plugin.  A user with valid credentials and access to one organization within Velociraptor can leverage the `query()` plugin from a notebook cell to execute VQL (Velociraptor Query Language) queries against other organizations, irrespective of their explicit permissions in those other organizations. This occurs because the plugin improperly uses the user's current ACL token for all queries, effectively granting the user the same level of access across all organizations as they have in their primary organization. This vulnerability allows for potentially broad data exfiltration and privilege escalation within a Velociraptor deployment.

## Attack Chain

1.  An attacker gains valid credentials for a user account within one organization in a vulnerable Velociraptor instance (version < 0.76.3).
2.  The attacker logs into the Velociraptor GUI.
3.  The attacker creates a new notebook or modifies an existing one.
4.  Within a notebook cell, the attacker uses the `query()` plugin with a crafted VQL query designed to access data from a different organization. For example, using `SELECT * FROM org_id='TARGET_ORG'`.
5.  The Velociraptor server processes the query using the attacker's existing ACL token, bypassing the organization's access controls.
6.  The server returns data from the target organization to the attacker.
7.  The attacker analyzes the retrieved data, potentially gaining access to sensitive information or identifying further targets within the compromised Velociraptor instance.
8.  The attacker uses the information gathered to perform actions in other organizations, based on the permissions of their initial account.

## Impact

Successful exploitation of CVE-2026-6290 could allow an attacker to gain unauthorized access to sensitive data stored within different organizations managed by the same Velociraptor instance.  This could lead to the exfiltration of confidential information, potential privilege escalation within targeted organizations, and a compromise of the overall security posture of the affected environment. The severity is compounded by the fact that it's a logic error within a security product, making it harder to detect and remediate without patching. The CVSS v3.1 score is 8.0 HIGH, indicating a significant risk.

## Recommendation

*   Immediately upgrade all Velociraptor installations to version 0.76.3 or later to patch CVE-2026-6290.
*   Prioritize reviewing Velociraptor user accounts and their assigned organizational access to identify potentially compromised accounts.
*   Deploy the Sigma rule provided in this brief to detect anomalous use of the `query()` plugin that targets different organizations than the user's primary organization.
*   Monitor Velociraptor server logs for any unexpected access patterns or data retrieval attempts originating from the `query()` plugin.
