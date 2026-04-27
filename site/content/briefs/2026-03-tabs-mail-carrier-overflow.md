---
title: Tabs Mail Carrier 2.5.1 MAIL FROM Buffer Overflow Vulnerability
slug: 2026-03-tabs-mail-carrier-overflow
description: Tabs Mail Carrier 2.5.1 is vulnerable to a buffer overflow in the MAIL FROM SMTP command, allowing remote attackers to execute arbitrary code by sending a crafted MAIL FROM parameter with an oversized buffer to overwrite the EIP register and execute a bind shell payload via port 25.
date: "2026-03-24T12:16:07Z"
severities:
  - critical
tags:
  - cve-2019-25646
  - buffer-overflow
  - smtp
  - code-execution
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25646
  - https://www.exploit-db.com/exploits/46547
  - https://www.vulncheck.com/advisories/tabs-mail-carrier-buffer-overflow-via-mail-from
rules:
  - title: Detecting SMTP MAIL FROM Buffer Overflow
    description: Detects potential buffer overflow attacks exploiting the MAIL FROM command in SMTP services by identifying abnormally long MAIL FROM commands.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - network_connection
      - windows
  - title: Detect Connection to SMTP Port 25 from Unusual Process
    description: Detects connections to SMTP port 25 initiated by processes that are not typically associated with email sending, which might indicate malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.003
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

Tabs Mail Carrier 2.5.1 is susceptible to a critical buffer overflow vulnerability (CVE-2019-25646) affecting the MAIL FROM SMTP command. This flaw enables unauthenticated remote attackers to execute arbitrary code on the affected system. The vulnerability stems from insufficient bounds checking when processing the MAIL FROM parameter. By sending a specially crafted MAIL FROM command containing an oversized buffer, an attacker can overwrite the EIP register, hijack control flow, and ultimately…
