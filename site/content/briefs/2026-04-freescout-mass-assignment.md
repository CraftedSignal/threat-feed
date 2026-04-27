---
title: FreeScout Mass Assignment Vulnerability (CVE-2026-40569)
slug: 2026-04-freescout-mass-assignment
description: FreeScout versions prior to 1.8.213 contain a mass assignment vulnerability allowing authenticated admins to modify sensitive mailbox settings by injecting parameters into connection settings requests, leading to email exfiltration and account compromise.
date: "2026-04-22T12:00:00Z"
severities:
  - high
tags:
  - freescout
  - mass-assignment
  - vulnerability
  - email-exfiltration
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-40569
    cvss: 9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40569
rules:
  - title: Detect FreeScout Mailbox Settings Modification via POST Request
    description: Detects POST requests to the mailbox settings endpoints with suspicious parameters indicating potential mass assignment exploitation.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - webserver
      - linux
  - title: Detect FreeScout Auto BCC Setting Change
    description: Detects modifications to the auto_bcc setting, which can indicate malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

FreeScout, a self-hosted help desk and shared mailbox platform, is vulnerable to a mass assignment flaw (CVE-2026-40569) in versions prior to 1.8.213. The vulnerability resides in the `connectionIncomingSave()` and `connectionOutgoingSave()` methods within `app/Http/Controllers/MailboxesController.php`.  These methods lack proper input validation, allowing an authenticated administrator to overwrite critical mailbox settings by injecting arbitrary parameters into legitimate connection setting…
