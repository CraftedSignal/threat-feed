---
title: Critical Vulnerabilities in SolarWinds Serv-U Allow Remote Code Execution
slug: 2026-02-solarwinds-servu-rce
description: Multiple critical vulnerabilities in SolarWinds Serv-U MFT and FTP Server allow remote code execution, potentially leading to system compromise.
date: "2026-02-26T12:00:00Z"
severities:
  - critical
tags:
  - solarwinds
  - serv-u
  - rce
  - vulnerability
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0006
    tactic_name: Execution
    technique_id: T1059.001
    technique_name: 'Command and Scripting Interpreter: PowerShell'
references:
  - https://ccb.belgium.be/advisories/warning-critical-vulnerabilities-solarwinds-serv-u-servers-can-be-exploited-remote-code
  - https://documentation.solarwinds.com/en/success_center/servu/content/release_notes/servu_15-5-4_release_notes.htm
  - https://www.solarwinds.com/trust-center/security-advisories/cve-2025-40538
  - https://www.solarwinds.com/trust-center/security-advisories/cve-2025-40539
  - https://www.solarwinds.com/trust-center/security-advisories/cve-2025-40540
  - https://www.solarwinds.com/trust-center/security-advisories/cve-2025-40541
  - https://thehackernews.com/2026/02/solarwinds-patches-4-critical-serv-u.html
rules:
  - title: Suspicious Process Spawned by Serv-U
    description: Detects suspicious processes spawned by Serv-U processes, potentially indicating exploitation.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Serv-U Creating System Admin User (CVE-2025-40538)
    description: Detects creation of a system admin user, which could indicate exploitation of CVE-2025-40538.
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

On February 25, 2026, the Centre for Cybersecurity Belgium (CCB) issued an advisory regarding four critical vulnerabilities (CVE-2025-40538, CVE-2025-40539, CVE-2025-40540, CVE-2025-40541) in SolarWinds Serv-U MFT and FTP Server. These vulnerabilities, if exploited, can lead to remote code execution (RCE) on the affected systems.  The Serv-U products are file transfer solutions widely used by organizations. While there's no current indication of active exploitation as of the advisory's release…
