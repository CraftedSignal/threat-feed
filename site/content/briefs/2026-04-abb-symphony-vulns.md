---
title: ABB Ability Symphony Plus Engineering Vulnerabilities Allow Remote Code Execution
slug: 2026-04-abb-symphony-vulns
description: Multiple vulnerabilities in ABB Ability Symphony Plus Engineering, stemming from underlying PostgreSQL flaws, could allow a remote attacker with network access to execute arbitrary code and compromise the system.
date: "2026-04-30T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - vulnerability
  - ics
  - postgresql
vendors:
  - ABB
products:
  - ABB Ability Symphony Plus S+ Engineering 2.2
  - ABB Ability Symphony Plus S+ Engineering 2.3
  - ABB Ability Symphony Plus S+ Engineering 2.3 RU1
  - ABB Ability Symphony Plus S+ Engineering 2.3 RU2
  - ABB Ability Symphony Plus S+ Engineering 2.3 RU3
  - ABB Ability Symphony Plus S+ Engineering 2.4
  - ABB Ability Symphony Plus S+ Engineering 2.4 SP1
  - ABB Ability Symphony Plus S+ Engineering 2.4 SP2
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1569
    technique_name: System Services
cves:
  - id: CVE-2023-5869
    cvss: 8.8
    epss: 0.01652
  - id: CVE-2023-39417
    cvss: 7.5
    epss: 0.00677
  - id: CVE-2024-7348
    cvss: 8.8
    epss: 0.00764
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-06
  - https://www.cve.org/CVERecord?id=CVE-2023-5869
  - https://www.cve.org/CVERecord?id=CVE-2023-39417
  - https://www.cve.org/CVERecord?id=CVE-2024-7348
rules:
  - title: Detect Suspicious PostgreSQL Utility Execution
    description: Detects execution of PostgreSQL utilities often used in TOCTOU race condition exploitation (CVE-2024-7348).
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Detect SQL Injection in PostgreSQL Logs
    description: Detects potential SQL injection attempts in PostgreSQL logs based on common injection keywords and syntax (CVE-2023-39417).
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

ABB Ability Symphony Plus Engineering versions 2.2 through 2.4 SP2 are susceptible to multiple vulnerabilities originating in the included PostgreSQL database. An attacker gaining access to the S+ Client Server network could exploit CVE-2023-5869 (Integer Overflow), CVE-2023-39417 (SQL Injection), and CVE-2024-7348 (TOCTOU race condition) to execute arbitrary code and potentially compromise the entire ABB system. This poses a significant risk to organizations in critical infrastructure sectors, including Chemical, Critical Manufacturing, Energy, and Water/Wastewater, as these systems are vital for operational control and safety. Successful exploitation could result in loss of control, data breaches, or disruption of essential services. ABB released S+ Engineering 2.4 SP2 RU1 in December 2024 as a fix.

## Attack Chain

1.  Attacker gains initial access to the target network, specifically the S+ Client Server network, possibly through existing vulnerabilities or misconfigurations.
2.  Attacker authenticates to the PostgreSQL database server used by ABB Ability Symphony Plus Engineering.
3.  Attacker exploits CVE-2023-5869 by providing crafted data to trigger an integer overflow, enabling arbitrary code execution.
4.  Alternatively, the attacker exploits CVE-2023-39417 by injecting malicious SQL code through extension scripts, leading to arbitrary code execution with administrator privileges.
5.  Alternatively, the attacker exploits CVE-2024-7348, leveraging a TOCTOU race condition to execute arbitrary SQL functions with elevated privileges using a PostgreSQL utility.
6.  The attacker executes arbitrary code within the context of the compromised ABB Ability Symphony Plus Engineering application or the underlying PostgreSQL database.
7.  The attacker leverages the compromised system to move laterally within the OT network, potentially targeting other critical systems or data repositories.
8.  Attacker achieves complete compromise of the ABB Ability Symphony Plus Engineering system, allowing manipulation of industrial processes, data exfiltration, or denial of service.

## Impact

Successful exploitation of these vulnerabilities in ABB Ability Symphony Plus Engineering can have severe consequences, particularly in critical infrastructure sectors. Affected sectors include chemical, critical manufacturing, energy, and water/wastewater facilities worldwide. A compromised system could allow attackers to manipulate industrial processes, leading to equipment damage, environmental incidents, or disruption of essential services like power generation or water treatment. The vulnerabilities could allow attackers to gain unauthorized access to sensitive data, intellectual property, or control systems, resulting in significant financial losses, reputational damage, and potential safety risks.

## Recommendation

*   Immediately upgrade ABB Ability Symphony Plus Engineering to version 2.4 SP2 RU1 (re-leased in December 2024) or later, as recommended by ABB, to address the identified vulnerabilities (Vendor fix).
*   Review and enforce network segmentation and firewall configurations to restrict access to the S+ client/server network, mitigating the risk of external attackers exploiting these vulnerabilities (Mitigation).
*   Monitor network traffic for suspicious activity indicative of PostgreSQL exploitation attempts. Deploy the Sigma rule `Detect Suspicious PostgreSQL Utility Execution` to identify potential exploitation of CVE-2024-7348.
*   Enable logging of PostgreSQL queries and analyze logs for SQL injection attempts, specifically looking for suspicious use of extension scripts. Deploy the Sigma rule `Detect SQL Injection in PostgreSQL Logs` to identify potential exploitation of CVE-2023-39417.
