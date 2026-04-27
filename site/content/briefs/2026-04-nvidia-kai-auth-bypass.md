---
title: NVIDIA KAI Scheduler Authentication Bypass Vulnerability
slug: 2026-04-nvidia-kai-auth-bypass
description: CVE-2026-24177 describes an authentication bypass vulnerability in NVIDIA KAI Scheduler that could allow unauthorized access to API endpoints, leading to information disclosure.
date: "2026-04-22T12:00:00Z"
severities:
  - medium
exploited: true
tags:
  - vulnerability
  - authentication-bypass
  - nvidia
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Software Discovery
cves:
  - id: CVE-2026-24177
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-24177
  - https://nvidia.custhelp.com/app/answers/detail/a_id/5818
  - https://www.cve.org/CVERecord?id=CVE-2026-24177
rules:
  - title: Detect Unauthorized Access to NVIDIA KAI Scheduler API
    description: Detects attempts to access NVIDIA KAI Scheduler API endpoints without proper authorization.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1552
    data_sources:
      - webserver
      - linux
  - title: Detect NVIDIA KAI Scheduler API Endpoint Access
    description: Detects access to NVIDIA KAI Scheduler API endpoints. This rule should be tuned to filter out legitimate access.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-24177 details a security flaw within the NVIDIA KAI Scheduler. This vulnerability stems from a lack of proper authentication mechanisms for critical API endpoints. An attacker exploiting this flaw could potentially bypass authorization checks and gain unauthorized access to sensitive functionalities. Successful exploitation leads to information disclosure. The affected product is NVIDIA KAI Scheduler. As of April 2026, exploitation in the wild has not been confirmed, but the potential…
