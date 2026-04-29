---
title: Marimo Pre-Authentication Remote Code Execution Vulnerability (CVE-2026-39987)
slug: 2026-04-marimo-rce
description: CVE-2026-39987 is a pre-authentication remote code execution vulnerability in Marimo, enabling unauthenticated attackers to execute arbitrary system commands.
date: "2026-04-24T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - CVE-2026-39987
  - rce
  - vulnerability
vendors:
  - Marimo
products:
  - Marimo
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1219
    technique_name: Exploitation of Remote Services
cves:
  - id: CVE-2026-39987
    cvss: 9.8
    epss: 0.55209
references:
  - https://www.cve.org/CVERecord?id=CVE-2026-39987
  - https://github.com/marimo-team/marimo/security/advisories/GHSA-2679-6mx9-h9xc
  - https://nvd.nist.gov/vuln/detail/CVE-2026-39987
rules:
  - title: Detect Marimo Exploitation Attempt
    description: Detects potential exploitation attempts targeting CVE-2026-39987 based on suspicious HTTP requests to the Marimo server.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1219
    data_sources:
      - webserver
      - linux
  - title: Detect Marimo Post-Exploitation Activity - Suspicious Process Creation
    description: Detects suspicious process creation from the Marimo application, which may indicate command execution after successful exploitation.
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

A pre-authentication remote code execution vulnerability, CVE-2026-39987, exists within the Marimo application. This vulnerability allows an unauthenticated attacker to gain shell access and execute arbitrary system commands on the affected system. Given the nature of the vulnerability, all versions of Marimo are potentially affected unless patched or mitigated. Successful exploitation could lead to complete system compromise, data theft, or denial of service. The vulnerability was publicly disclosed in April 2026 and organizations using Marimo should take immediate action to address it.

## Attack Chain

1.  The attacker sends a specially crafted request to the Marimo server.
2.  The Marimo application fails to properly validate or sanitize the input within the request.
3.  This input is processed by the server without proper authorization checks.
4.  Due to the lack of input validation, the attacker injects malicious code into the application.
5.  The injected code is executed with the privileges of the Marimo process.
6.  The attacker gains shell access to the underlying operating system.
7.  The attacker executes arbitrary system commands, potentially installing malware or exfiltrating data.
8.  The attacker establishes persistence for continued access to the compromised system.

## Impact

Successful exploitation of CVE-2026-39987 allows an unauthenticated attacker to execute arbitrary system commands on a server running Marimo. This could lead to complete compromise of the system, including data theft, malware installation, or denial of service. The number of potential victims is dependent on the number of Marimo deployments, but given the pre-authentication nature of the vulnerability, any unpatched instance is at risk. Sectors particularly at risk are those relying on Marimo for critical services or data management.

## Recommendation

*   Apply mitigations provided by the vendor to address CVE-2026-39987 or discontinue use of the product.
*   Deploy the Sigma rule "Detect Marimo Exploitation Attempt" to identify potential exploitation attempts targeting CVE-2026-39987 within web server logs.
*   Monitor network traffic for suspicious outbound connections originating from Marimo servers, which could indicate successful exploitation.
*   Follow applicable BOD 22-01 guidance for cloud services if Marimo is deployed in a cloud environment.
