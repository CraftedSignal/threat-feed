---
title: Dell AppSync 4.6.0 Incorrect Permission Assignment Vulnerability
slug: 2026-04-dell-appsync-privesc
description: Dell AppSync version 4.6.0 contains an incorrect permission assignment vulnerability that allows a low-privileged attacker with local access to elevate privileges on the system.
date: "2026-04-01T13:16:33Z"
severities:
  - high
tags:
  - dell
  - appsync
  - privilege-escalation
  - cve-2026-22768
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-22768
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-22768
  - https://www.dell.com/support/kbdoc/en-us/000446965/dsa-2026-163-security-update-for-dell-appsync-vulnerabilities
rules:
  - title: Detect Suspicious Process Creation in Dell AppSync Directory
    description: Detects the creation of suspicious processes within the Dell AppSync installation directory, which may indicate exploitation of CVE-2026-22768.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect File Modification in Dell AppSync Configuration Directory
    description: Detects modification of files within the Dell AppSync configuration directory, which may indicate exploitation of CVE-2026-22768 through incorrect permission assignment.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
rules_count: 2
---

Dell AppSync version 4.6.0 is vulnerable to an incorrect permission assignment issue. A local attacker with low privileges can exploit this vulnerability to escalate their privileges on the affected system. This vulnerability, identified as CVE-2026-22768, could allow an attacker to gain unauthorized access to sensitive data or execute arbitrary code with elevated privileges. Successful exploitation requires local access and user interaction (UI:R). This vulnerability poses a significant risk…
