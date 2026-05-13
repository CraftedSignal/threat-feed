---
title: Mapfish Print Remote Code Injection Vulnerability in Dynamic Table (CVE-2026-44672)
slug: 2026-05-mapfish-rce
description: An unauthenticated remote code injection vulnerability (CVE-2026-44672) exists in Mapfish Print's Dynamic table functionality, allowing attackers to execute arbitrary code on the server.
date: "2026-05-13T01:37:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - remote-code-execution
  - code-injection
  - mapfish
  - web-application
vendors:
  - Mapfish
products:
  - print-lib
  - print-servlet
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-q7m6-wpvf-mvwx
  - CVE-2026-44672
rules:
  - title: Detect CVE-2026-44672 Exploitation Attempt - Mapfish Print Dynamic Table RCE
    description: Detects potential exploitation attempts of CVE-2026-44672 in Mapfish Print by identifying suspicious HTTP requests to the Dynamic table functionality.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
  - title: Detect CVE-2026-44672 Post-Exploitation - Suspicious Process Spawn
    description: Detects potential post-exploitation activity of CVE-2026-44672 in Mapfish Print by identifying suspicious process spawned by Mapfish Print process
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A critical remote code injection vulnerability, tracked as CVE-2026-44672, has been identified in the Dynamic table component of Mapfish Print. This flaw allows an unauthenticated attacker to execute arbitrary code on the server. The vulnerability affects multiple versions of the `print-lib` and `print-servlet` components, specifically versions between 3.23.0 and 3.28.28, 3.29.0 and 3.30.30, 3.31.0 and 3.31.21, 3.32.0 and 3.33.14, and 3.34.0 and 4.0.3. Successful exploitation grants the attacker complete control over the affected Mapfish Print instance.

## Attack Chain

1.  The attacker crafts a malicious HTTP request targeting the Dynamic table functionality in Mapfish Print.
2.  This request contains a payload designed to inject arbitrary code into the server-side processing logic.
3.  The injected code leverages a vulnerability in how Mapfish Print handles data within the Dynamic table component.
4.  Mapfish Print processes the malicious request, inadvertently executing the injected code.
5.  The injected code gains access to the underlying operating system with the privileges of the Mapfish Print application.
6.  The attacker uses the gained access to execute system commands.
7.  The attacker deploys a reverse shell to establish a persistent connection to the compromised server.
8.  The attacker pivots within the network to compromise additional systems or exfiltrate sensitive data.

## Impact

Successful exploitation of CVE-2026-44672 allows unauthenticated attackers to execute arbitrary code on systems running vulnerable versions of Mapfish Print. This can lead to complete system compromise, data theft, and disruption of services. The number of affected installations is currently unknown, but organizations using Mapfish Print for critical mapping and printing services are at high risk.

## Recommendation

*   Immediately upgrade Mapfish Print `print-lib` and `print-servlet` components to a patched version greater than or equal to 3.28.28, 3.30.30, 3.31.21, 3.33.14, or 4.0.3, as indicated in the advisory.
*   Deploy the Sigma rule to detect exploitation attempts targeting CVE-2026-44672 by monitoring for suspicious HTTP requests.
*   Review network traffic to Mapfish Print servers for unusual patterns or connections originating from unexpected locations.
*   Implement strict input validation and sanitization measures to prevent code injection vulnerabilities.
