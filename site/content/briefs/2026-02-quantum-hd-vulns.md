---
title: Johnson Controls Frick Controls Quantum HD Multiple Vulnerabilities
slug: 2026-02-quantum-hd-vulns
description: Multiple vulnerabilities in Johnson Controls, Inc. Frick Controls Quantum HD versions <=10.22 can lead to pre-authentication remote code execution, information leak, or denial of service.
date: "2026-02-26T12:00:00Z"
severities:
  - critical
tags:
  - ics
  - ot
  - vulnerability
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021.001
    technique_name: 'Remote Services: RDP'
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-057-01
  - https://nvd.nist.gov/vuln/detail/CVE-2026-21654
  - https://nvd.nist.gov/vuln/detail/CVE-2026-21656
  - https://nvd.nist.gov/vuln/detail/CVE-2026-21657
  - https://nvd.nist.gov/vuln/detail/CVE-2026-21658
  - https://nvd.nist.gov/vuln/detail/CVE-2026-21659
  - https://nvd.nist.gov/vuln/detail/CVE-2026-21660
  - https://www.johnsoncontrols.com/trust-center/cybersecurity/security-advisories
rules:
  - title: Detect Attempted Access to Frick Controls Quantum HD Web Interface
    description: Detects attempts to access the web interface of Frick Controls Quantum HD devices, which may indicate reconnaissance or exploitation attempts.
    platform: sigma
    severity: informational
    tactics:
      - reconnaissance
    techniques:
      - T1595.002
    data_sources:
      - network_connection
      - zeek
  - title: Detect Exploitation Attempts via URI
    description: Detects URI strings known to be associated with code injection attacks
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - zeek
rules_count: 2
---

Multiple vulnerabilities have been identified in Johnson Controls, Inc. Frick Controls Quantum HD versions 10.22 and earlier. These vulnerabilities, including CVE-2026-21654, CVE-2026-21656, CVE-2026-21657, CVE-2026-21658, CVE-2026-21659, and CVE-2026-21660, can be exploited to achieve pre-authentication remote code execution, information leaks, or denial of service. Given that Frick Controls Quantum HD is deployed worldwide, particularly in the Food and Agriculture sector, these…
