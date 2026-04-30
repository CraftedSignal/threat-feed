---
title: Provectus Kafka UI Code Injection Vulnerability (CVE-2026-5562)
slug: 2026-04-kafka-ui-code-injection
description: A code injection vulnerability exists in provectus kafka-ui up to version 0.7.2, specifically affecting the validateAccess function within the /api/smartfilters/testexecutions endpoint, allowing remote attackers to inject code.
date: "2026-04-05T11:16:56Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - code-injection
  - kafka-ui
  - vulnerability
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server-Side Code Injection
cves:
  - id: CVE-2026-5562
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5562
  - https://vuldb.com/vuln/355332
rules:
  - title: Detect Kafka UI Code Injection Attempt
    description: Detects potential code injection attempts targeting the /api/smartfilters/testexecutions endpoint in Provectus Kafka UI.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1505
    data_sources:
      - webserver
      - linux
  - title: Detect Kafka UI Code Injection Exploit (Process Creation)
    description: Detects process creation events that could indicate successful code injection via Kafka UI.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A code injection vulnerability, identified as CVE-2026-5562, affects provectus kafka-ui versions up to 0.7.2. The vulnerability resides within the `validateAccess` function of the `/api/smartfilters/testexecutions` endpoint, potentially allowing remote attackers to inject arbitrary code. This vulnerability allows for remote code execution, potentially leading to complete system compromise. The vendor was notified but did not respond. A public exploit is reportedly available, increasing the risk of exploitation. This poses a significant risk to organizations utilizing vulnerable versions of Kafka UI.

## Attack Chain

1.  An attacker identifies a vulnerable Kafka UI instance running a version prior to 0.7.3.
2.  The attacker crafts a malicious HTTP request targeting the `/api/smartfilters/testexecutions` endpoint.
3.  Within the crafted request, the attacker injects malicious code into the `validateAccess` function parameters.
4.  The Kafka UI application processes the request without proper sanitization of the injected code.
5.  The injected code is executed within the context of the application server.
6.  The attacker gains the ability to execute arbitrary commands on the server.
7.  The attacker establishes a persistent connection to the compromised system, potentially via a reverse shell.
8.  The attacker pivots to other systems or resources within the network, potentially leading to data exfiltration or other malicious activities.

## Impact

Successful exploitation of CVE-2026-5562 can lead to arbitrary code execution on the server hosting the Provectus Kafka UI. This could allow attackers to gain complete control of the affected system, potentially leading to data breaches, service disruption, or further lateral movement within the network. Due to the public availability of a reported exploit, organizations running vulnerable versions of Kafka UI are at increased risk of attack. The lack of vendor response also raises concerns about future patches or mitigations.

## Recommendation

*   Upgrade Provectus Kafka UI to a version greater than 0.7.2 to remediate CVE-2026-5562.
*   Implement input validation and sanitization on the `/api/smartfilters/testexecutions` endpoint to prevent code injection attacks.
*   Deploy the Sigma rule `Detect Kafka UI Code Injection Attempt` to identify potential exploitation attempts targeting CVE-2026-5562.
*   Monitor web server logs for suspicious POST requests to `/api/smartfilters/testexecutions` containing potentially malicious code.
