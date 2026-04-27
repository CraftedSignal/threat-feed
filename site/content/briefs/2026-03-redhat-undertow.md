---
title: Red Hat Undertow Multiple Vulnerabilities Allow Security Bypass
slug: 2026-03-redhat-undertow
description: An anonymous remote attacker can exploit multiple vulnerabilities in Red Hat Undertow to bypass security measures, manipulate data, and disclose sensitive information.
date: "2026-03-30T11:24:09Z"
severities:
  - high
tags:
  - redhat
  - undertow
  - security-bypass
  - information-disclosure
  - data-manipulation
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1020
    technique_name: Automated Exfiltration
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-0907
rules:
  - title: Detect Suspicious URI Access on Undertow Servers
    description: Detects suspicious URI patterns indicative of potential exploit attempts on Red Hat Undertow servers.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Large HTTP Request targeting Undertow Servers
    description: Detects unusually large HTTP requests which could be indicative of buffer overflow exploits
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Red Hat Undertow is vulnerable to multiple security flaws that could allow an unauthenticated, remote attacker to bypass security restrictions, manipulate data, and expose sensitive information. The specifics of these vulnerabilities are not detailed, but the advisory indicates a high severity due to the potential impact. Without further information, defenders should assume all versions of Undertow are affected. This lack of specific CVEs or exploitation details makes precise mitigation…
