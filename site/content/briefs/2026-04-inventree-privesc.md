---
title: InvenTree Privilege Escalation via API Abuse (CVE-2026-35476)
slug: 2026-04-inventree-privesc
description: A non-staff authenticated user can elevate their account to a staff level via a POST request against their user account endpoint in InvenTree versions prior to 1.2.7 and 1.3.0 due to improperly configured API write permissions.
date: "2026-04-08T20:16:24Z"
severities:
  - high
tags:
  - inventree
  - privilege-escalation
  - cve-2026-35476
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-35476
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35476
  - https://github.com/inventree/InvenTree/security/advisories/GHSA-r8q5-3595-3jh2
  - https://docs.inventree.org/en/stable/concepts/threat_model/#assumed-trust
ioc_counts:
  email: 1
rules:
  - title: InvenTree User Staff Status Modification via API
    description: Detects POST requests to the InvenTree API that attempt to modify a user's staff status.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: InvenTree Suspicious API POST Request
    description: Detects POST requests with is_staff=true to the InvenTree API server to identify potential exploit attempts.
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

CVE-2026-35476 is a privilege escalation vulnerability affecting InvenTree, an open-source inventory management system. The vulnerability resides in versions prior to 1.2.7 and 1.3.0. It allows a non-staff authenticated user to elevate their account privileges to a staff level. This is achieved by sending a specially crafted POST request to the user's account endpoint. The root cause is due to improperly configured write permissions on the API endpoint, enabling unauthorized modification of the…
