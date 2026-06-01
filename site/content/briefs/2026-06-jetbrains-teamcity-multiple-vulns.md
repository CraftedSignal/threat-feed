---
title: Multiple Vulnerabilities in JetBrains TeamCity
slug: 2026-06-jetbrains-teamcity-multiple-vulns
description: Multiple vulnerabilities in JetBrains TeamCity allow an attacker to disclose information, perform a cross-site scripting attack, bypass security measures, and execute arbitrary program code.
date: "2026-06-01T10:59:31Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - vulnerability
  - code-execution
  - xss
  - information-disclosure
vendors:
  - JetBrains
products:
  - TeamCity
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal on Host
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-1758
rules:
  - title: Detect Suspicious TeamCity Process Execution
    description: Detects suspicious processes spawned by the TeamCity server process which could indicate command execution.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Detect TeamCity Cross-Site Scripting (XSS) Attempt
    description: Detects potential Cross-Site Scripting attacks against TeamCity by identifying requests containing common XSS payloads.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

JetBrains TeamCity is susceptible to multiple vulnerabilities that can be exploited by an attacker to achieve several malicious objectives. These include unauthorized information disclosure, the execution of cross-site scripting (XSS) attacks, bypassing existing security measures implemented within the application, and ultimately, the execution of arbitrary program code. These vulnerabilities pose a significant risk to the confidentiality, integrity, and availability of systems utilizing affected versions of TeamCity. Defenders should prioritize patching to mitigate potential exploitation.

## Attack Chain

1.  Attacker identifies a vulnerable TeamCity instance.
2.  Attacker exploits an information disclosure vulnerability to gather sensitive information about the TeamCity configuration, such as internal network structure, user credentials, or API keys.
3.  Attacker leverages gathered information to craft a malicious payload suitable for a Cross-Site Scripting (XSS) attack.
4.  Attacker injects the XSS payload into a vulnerable TeamCity page, targeting administrators or users with elevated privileges.
5.  Attacker exploits the XSS vulnerability to steal user session cookies or inject malicious JavaScript to perform actions on behalf of the victim.
6.  Attacker exploits a security bypass vulnerability, potentially to gain unauthorized access to restricted areas or functionalities of TeamCity.
7.  Attacker leverages prior gained access and information to exploit a code execution vulnerability.
8.  Attacker executes arbitrary code on the TeamCity server, leading to complete system compromise, data exfiltration, or further lateral movement within the network.

## Impact

Successful exploitation of these vulnerabilities can lead to a complete compromise of the TeamCity server and the sensitive data it manages. Attackers could gain access to build configurations, source code, and deployment credentials. This can lead to supply chain attacks, data breaches, and significant financial and reputational damage. The number of potential victims is dependent on the scope of TeamCity usage within an organization, but the impact is critical due to the nature of the data managed by TeamCity.

## Recommendation

*   Upgrade JetBrains TeamCity to the latest version to patch the reported vulnerabilities.
*   Deploy the provided Sigma rules to your SIEM to detect potential exploitation attempts targeting TeamCity.
*   Implement strict input validation and output encoding to prevent XSS attacks.
*   Review and enforce strong access control policies to minimize the impact of security bypass vulnerabilities.
*   Monitor TeamCity logs for suspicious activity, such as unauthorized access attempts or code execution events, to identify and respond to potential attacks.
