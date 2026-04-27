---
title: Copeland XWEB and XWEB Pro Multiple Vulnerabilities
slug: 2026-02-copeland-xweb-vulns
description: Multiple vulnerabilities in Copeland XWEB and XWEB Pro versions 1.12.1 and earlier could allow attackers to bypass authentication, inject commands, and execute arbitrary code, leading to complete system compromise.
date: "2026-02-26T12:00:00Z"
severities:
  - critical
tags:
  - copeland
  - xweb
  - vulnerability
  - ics
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-057-10
  - https://nvd.nist.gov/vuln/detail/CVE-2026-25085
  - https://nvd.nist.gov/vuln/detail/CVE-2026-21718
  - https://nvd.nist.gov/vuln/detail/CVE-2026-24663
  - https://nvd.nist.gov/vuln/detail/CVE-2026-21389
rules:
  - title: Detect Suspicious Request to Libraries Install Endpoint
    description: Detects suspicious requests to the /libraries/install endpoint, which is vulnerable to OS command injection (CVE-2026-24663).
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - web
      - copeland_xweb
  - title: Detect Suspicious Request to Contacts Import Endpoint
    description: Detects suspicious requests to the /contacts/import endpoint, which is vulnerable to OS command injection (CVE-2026-21389).
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - web
      - copeland_xweb
rules_count: 2
---

Copeland XWEB and XWEB Pro are web-enabled controllers used for managing refrigeration and HVAC systems in commercial facilities worldwide. CISA has released an advisory detailing multiple critical vulnerabilities affecting versions 1.12.1 and earlier of XWEB 300D PRO, XWEB 500D PRO, and XWEB 500B PRO. These vulnerabilities, including authentication bypasses (CVE-2026-25085, CVE-2026-21718), OS command injection flaws (CVE-2026-24663, CVE-2026-21389), and others, can be exploited to achieve…
