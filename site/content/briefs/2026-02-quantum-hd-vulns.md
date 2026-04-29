---
title: Johnson Controls Frick Controls Quantum HD Multiple Vulnerabilities
slug: 2026-02-quantum-hd-vulns
description: Multiple vulnerabilities in Johnson Controls, Inc. Frick Controls Quantum HD versions <=10.22 can lead to pre-authentication remote code execution, information leak, or denial of service.
date: "2026-02-26T12:00:00Z"
type: coverage
types:
  - coverage
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

Multiple vulnerabilities have been identified in Johnson Controls, Inc. Frick Controls Quantum HD versions 10.22 and earlier. These vulnerabilities, including CVE-2026-21654, CVE-2026-21656, CVE-2026-21657, CVE-2026-21658, CVE-2026-21659, and CVE-2026-21660, can be exploited to achieve pre-authentication remote code execution, information leaks, or denial of service. Given that Frick Controls Quantum HD is deployed worldwide, particularly in the Food and Agriculture sector, these vulnerabilities pose a significant risk. Johnson Controls recommends upgrading to Quantum HD Unity, version 12 or higher, to mitigate these risks. Versions 10.22 through 11 are no longer supported.

## Attack Chain

1.  An attacker identifies a vulnerable Frick Controls Quantum HD device exposed to the network.
2.  The attacker sends a specially crafted request to the device exploiting the input validation vulnerabilities (CVE-2026-21654, CVE-2026-21656, CVE-2026-21657, CVE-2026-21658).
3.  Due to the insufficient validation of input, the crafted request allows the attacker to inject malicious code into the system (CWE-78, CWE-94).
4.  The injected code is executed by the device, granting the attacker unauthorized access.
5.  The attacker leverages the code execution to perform further actions such as gaining access to sensitive information (information leak), or causing the device to crash (denial of service).
6.  If successful RCE is achieved, the attacker may use this to move laterally within the OT network.
7.  The attacker could then target other critical systems within the food and agriculture environment.

## Impact

Successful exploitation of these vulnerabilities can lead to severe consequences, especially in critical infrastructure sectors like Food and Agriculture. Attackers could remotely execute arbitrary code on the affected systems without authentication, potentially disrupting industrial processes, stealing sensitive data, or causing a complete shutdown of operations. With Quantum HD systems deployed globally, a widespread attack could affect numerous organizations, leading to significant financial losses and supply chain disruptions.

## Recommendation

*   Immediately upgrade all Frick Controls Quantum HD devices to the latest platform, Quantum HD Unity, version 12 or higher, as recommended by Johnson Controls (CVE-2026-21654, CVE-2026-21656, CVE-2026-21657, CVE-2026-21658, CVE-2026-21659, CVE-2026-21660).
*   After upgrading to version 12, verify full compliance with the hardening guide and apply all recommended security configurations.
*   Monitor network traffic for suspicious requests targeting Frick Controls Quantum HD devices (Network Connection logs).
*   Refer to Johnson Controls Product Security Advisory JCI-PSA-2026-05 for more detailed mitigation instructions at https://www.johnsoncontrols.com/trust-center/cybersecurity/security-advisories.
