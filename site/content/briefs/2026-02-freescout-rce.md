---
title: Critical Vulnerabilities in FreeScout Help Desk Allow Remote Code Execution
slug: 2026-02-freescout-rce
description: Critical vulnerabilities, CVE-2026-27636 and CVE-2026-27637, exist in FreeScout Help Desk that could be exploited to achieve remote code execution, potentially leading to data exfiltration and system compromise.
date: "2026-02-25T14:05:50Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - freescout
  - rce
  - vulnerability
  - apache
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505
    technique_name: Server Software Component
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://ccb.belgium.be/advisories/warning-critical-vulnerabilities-freescout-could-be-exploited-achieve-remote-code
  - https://github.com/freescout-help-desk/freescout/security/advisories/GHSA-mw88-x7j3-74vc
  - https://github.com/freescout-help-desk/freescout/security/advisories/GHSA-6gcm-v8xf-j9v9
rules:
  - title: Detect .htaccess File Uploads
    description: Detects the creation of .htaccess files, which could indicate exploitation of CVE-2026-27636
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1505.003
    data_sources:
      - file_event
      - linux
  - title: Detect .user.ini File Uploads
    description: Detects the creation of .user.ini files, which could indicate exploitation of CVE-2026-27636
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1505.003
    data_sources:
      - file_event
      - linux
rules_count: 2
---

FreeScout, a popular open-source help desk solution, is affected by two critical vulnerabilities, CVE-2026-27636 and CVE-2026-27637. Disclosed in February 2026, these vulnerabilities can be exploited independently or chained to achieve remote code execution. CVE-2026-27636 stems from insufficient file upload restrictions, while CVE-2026-27637 relates to predictable authentication tokens. Successful exploitation allows attackers to execute arbitrary system commands, read/write files, pivot to…
