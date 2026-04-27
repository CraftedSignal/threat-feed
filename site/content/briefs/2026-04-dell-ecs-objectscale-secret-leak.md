---
title: Dell ECS and ObjectScale Sensitive Information Logging Vulnerability (CVE-2026-28261)
slug: 2026-04-dell-ecs-objectscale-secret-leak
description: Dell Elastic Cloud Storage and ObjectScale are vulnerable to local privilege escalation due to sensitive information being logged, potentially allowing a low-privileged attacker with local access to expose secrets and gain unauthorized access.
date: "2026-04-08T13:16:41Z"
severities:
  - medium
tags:
  - cve-2026-28261
  - secret-leak
  - privilege-escalation
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
cves:
  - id: CVE-2026-28261
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-28261
  - https://www.dell.com/support/kbdoc/en-us/000449325/dsa-2026-143-security-update-for-dell-objectscale-prior-to-4-1-0-3-and-4-2-0-0-insertion-of-sensitive-information-into-log-file-vulnerability
rules:
  - title: Detect Access to Sensitive Log Files
    description: Detects access attempts to sensitive log files that may contain leaked secrets.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1003
    data_sources:
      - file_event
      - linux
  - title: Detect Configuration File Access
    description: Detects access attempts to sensitive configuration files that may contain leaked secrets.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1003
    data_sources:
      - file_event
      - linux
rules_count: 2
---

Dell Elastic Cloud Storage (ECS) version 3.8.1.7 and prior, and Dell ObjectScale versions prior to 4.1.0.3 and version 4.2.0.0, are vulnerable to sensitive information being logged. Identified as CVE-2026-28261, this vulnerability allows a low-privileged attacker with local access to potentially expose secrets stored within log files. Successful exploitation could allow the attacker to escalate their privileges and access the vulnerable system with the privileges of the compromised account…
