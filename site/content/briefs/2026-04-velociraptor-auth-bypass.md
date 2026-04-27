---
title: Velociraptor Authentication Bypass via query() Plugin
slug: 2026-04-velociraptor-auth-bypass
description: Velociraptor versions prior to 0.76.3 contain an authentication bypass vulnerability in the query() plugin, allowing authenticated users to access data from other organizations within the Velociraptor deployment, potentially leading to unauthorized data access and privilege escalation.
date: "2026-04-15T18:17:25Z"
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

Velociraptor, a powerful open-source endpoint detection and response (EDR) framework, is vulnerable to an authentication bypass issue affecting versions prior to 0.76.3. The vulnerability, identified as CVE-2026-6290, resides within the `query()` plugin.  A user with valid credentials and access to one organization within Velociraptor can leverage the `query()` plugin from a notebook cell to execute VQL (Velociraptor Query Language) queries against other organizations, irrespective of their…
