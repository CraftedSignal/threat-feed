---
title: Multiple Vulnerabilities in Roundcube
slug: 2026-04-roundcube-vulns
description: Multiple vulnerabilities in Roundcube allow an attacker to manipulate files, bypass security measures, perform cross-site scripting attacks, and disclose information.
date: "2026-04-21T08:06:54Z"
severities:
  - high
tags:
  - roundcube
  - vulnerability
  - xss
  - file-manipulation
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal on Host
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Host Information
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-0789
rules:
  - title: Roundcube File Upload
    description: Detects potential file upload attempts to Roundcube directories with suspicious file extensions.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Roundcube XSS Attempt
    description: Detects potential cross-site scripting (XSS) attacks targeting Roundcube.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Roundcube is a widely used, open-source webmail solution. The BSI advisory highlights multiple vulnerabilities within Roundcube that can be exploited by an attacker. These vulnerabilities allow for file manipulation, security bypass, cross-site scripting (XSS) attacks, and information disclosure. While the specific versions affected are not detailed, administrators are urged to investigate and apply necessary patches. Successful exploitation could lead to unauthorized access to sensitive email…
