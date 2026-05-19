---
title: ScadaBR Multiple Vulnerabilities Allow Remote Code Execution
slug: 2026-05-scadabr-rce
description: Multiple vulnerabilities exist in ScadaBR version 1.2.0, including CVE-2026-8602, CVE-2026-8603, CVE-2026-8604, and CVE-2026-8605, which could allow for unauthenticated remote code execution.
date: "2026-05-19T16:16:18Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - scada
  - ics
  - rce
  - command-injection
vendors:
  - ScadaBR
products:
  - ScadaBR 1.2.0
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-139-03
  - https://github.com/ScadaBR
  - https://www.cve.org/CVERecord?id=CVE-2026-8602
  - https://www.cve.org/CVERecord?id=CVE-2026-8603
  - https://www.cve.org/CVERecord?id=CVE-2026-8604
  - https://www.cve.org/CVERecord?id=CVE-2026-8605
  - https://cwe.mitre.org/data/definitions/306.html
  - https://cwe.mitre.org/data/definitions/78.html
  - https://cwe.mitre.org/data/definitions/352.html
  - https://cwe.mitre.org/data/definitions/798.html
rules:
  - title: Detects CVE-2026-8602 Exploitation — Unauthenticated HTTP GET Request to Inject Sensor Readings
    description: Detects CVE-2026-8602 exploitation — An unauthenticated attacker can send HTTP GET requests to inject arbitrary sensor readings.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detects CVE-2026-8603 Exploitation — OS Command Injection Attempt
    description: Detects CVE-2026-8603 exploitation — An attacker attempts to inject OS commands through a vulnerable parameter.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059
    data_sources:
      - webserver
  - title: Detects CVE-2026-8605 - Use of Hardcoded Credentials
    description: Detects CVE-2026-8605 - Detects authentication attempts using known hardcoded credentials.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 3
---

ScadaBR version 1.2.0 is affected by multiple vulnerabilities that could lead to unauthenticated remote code execution. These vulnerabilities include missing authentication for critical functions (CVE-2026-8602), OS command injection (CVE-2026-8603), cross-site request forgery (CSRF) (CVE-2026-8604), and the use of hard-coded credentials (CVE-2026-8605). Successful exploitation of these vulnerabilities could allow an attacker to inject arbitrary sensor readings, execute commands as root, trigger authenticated actions through a victim's session, or access the SCADA system as an administrator. These vulnerabilities impact critical infrastructure sectors including Critical Manufacturing, Dams, Chemical, Energy, Water, and Wastewater, with deployments worldwide.

## Attack Chain

1. An unauthenticated attacker sends an HTTP GET request to the SCADA system (CVE-2026-8602).
2. The system, lacking proper authentication, accepts the request.
3. The attacker injects arbitrary sensor readings into the SCADA system via the HTTP GET request (CVE-2026-8602).
4. An attacker leverages the CSRF vulnerability (CVE-2026-8604) by luring a logged-in user to a malicious webpage.
5. The malicious webpage triggers authenticated actions within the victim's session without their knowledge or consent.
6. The attacker exploits the OS command injection vulnerability (CVE-2026-8603) to execute commands as root on the SCADA system.
7. Alternatively, the attacker utilizes hard-coded credentials (CVE-2026-8605) to gain administrative access to the SCADA system.
8. With administrative access, the attacker manipulates critical control system functions, leading to potential disruption or damage.

## Impact

Successful exploitation of these vulnerabilities can lead to severe consequences, including manipulation of sensor data, unauthorized command execution at the root level, and complete system takeover. Given the affected sectors (Critical Manufacturing, Dams, Chemical, Energy, Water and Wastewater), a successful attack could result in significant disruption to essential services, environmental damage, or even physical harm. The lack of vendor response further exacerbates the risk.

## Recommendation

*   Apply network segmentation to minimize network exposure for all control system devices and ensure they are not directly accessible from the internet.
*   Place control system networks and remote devices behind firewalls, isolating them from business networks as recommended by CISA.
*   Monitor web server logs for suspicious HTTP GET requests without proper authentication headers targeting ScadaBR instances to detect potential CVE-2026-8602 exploitation attempts.
*   Implement stricter input validation and output encoding mechanisms to prevent OS command injection attacks as referenced in CVE-2026-8603 and CWE-78.
