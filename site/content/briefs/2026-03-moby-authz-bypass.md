---
title: Moby Authorization Plugin Bypass Vulnerability (CVE-2026-34040)
slug: 2026-03-moby-authz-bypass
description: A security vulnerability in Moby (prior to v29.3.1) allows attackers to bypass authorization plugins, potentially leading to unauthorized container access and privilege escalation.
date: "2026-03-31T03:15:57Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - containerization
  - authorization bypass
  - privilege escalation
  - cve-2026-34040
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
  - id: CVE-2026-34040
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34040
  - https://github.com/moby/moby/releases/tag/docker-v29.3.1
  - https://github.com/moby/moby/security/advisories/GHSA-x744-4wpc-v9h2
rules:
  - title: Detect Moby AuthZ Bypass Attempt
    description: Detects potential attempts to bypass authorization plugins in Moby by monitoring API requests.
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
  - title: Detect Moby API Request to Bypass Authorization
    description: Detects API requests targeting sensitive container operations without proper authorization headers, indicating a potential bypass attempt.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Moby is an open-source container framework widely used in containerization deployments. A critical security vulnerability, identified as CVE-2026-34040, affects Moby versions prior to 29.3.1. This flaw enables attackers to bypass configured authorization plugins (AuthZ), potentially granting them unauthorized access to container resources and functionalities. Successful exploitation could lead to privilege escalation within the container environment, allowing attackers to execute arbitrary…
