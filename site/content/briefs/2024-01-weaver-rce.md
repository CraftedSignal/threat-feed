---
title: Weaver E-cology Unauthenticated RCE via Dubbo API Debug Endpoint
slug: 2024-01-weaver-rce
description: Weaver E-cology 10.0 before 20260312 is vulnerable to unauthenticated remote code execution, allowing attackers to execute arbitrary commands by crafting a POST request to the /papi/esearch/data/devops/dubboApi/debug/method endpoint.
date: "2026-04-07T13:16:45Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - weaver
  - e-cology
  - rce
  - unauthenticated
  - cve-2026-22679
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1219
    technique_name: Remote Access Software
cves:
  - id: CVE-2026-22679
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-22679
rules:
  - title: Detect Weaver E-cology Dubbo API Exploitation Attempt
    description: Detects attempts to exploit the unauthenticated RCE vulnerability in Weaver E-cology's Dubbo API debug endpoint by monitoring POST requests with suspicious parameters.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1219
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious Activity After Weaver E-cology RCE (Process Creation)
    description: Detects suspicious process creation following a potential RCE on a Weaver E-cology server.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Suspicious File Creation After Weaver E-cology RCE
    description: Detects suspicious file creation following a potential RCE on a Weaver E-cology server, potentially indicating web shell deployment.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1505.003
    data_sources:
      - file_event
      - linux
rules_count: 3
---

Weaver (Fanwei) E-cology is susceptible to an unauthenticated remote code execution (RCE) vulnerability affecting version 10.0 prior to 20260312. The vulnerability exists in the `/papi/esearch/data/devops/dubboApi/debug/method` endpoint, stemming from exposed debug functionality. Exploitation allows unauthenticated attackers to execute arbitrary commands on the underlying system. The attack involves crafting malicious POST requests with attacker-controlled `interfaceName` and `methodName` parameters. Shadowserver Foundation observed initial exploitation attempts on 2026-03-31 (UTC). Due to the ease of exploitation and lack of authentication requirement, this vulnerability presents a significant risk.

## Attack Chain

1.  Attacker identifies a vulnerable Weaver E-cology 10.0 instance running a version prior to 20260312.
2.  Attacker crafts a malicious HTTP POST request targeting the `/papi/esearch/data/devops/dubboApi/debug/method` endpoint.
3.  The POST request includes the `interfaceName` and `methodName` parameters, which are set to values designed to invoke command execution helpers.
4.  The server processes the request without authentication due to the vulnerability.
5.  The application invokes the specified `methodName` within the `interfaceName`, leading to the execution of attacker-controlled code.
6.  The attacker-controlled code executes commands on the server, such as establishing a reverse shell.
7.  The attacker gains remote access to the server.
8.  The attacker pivots within the network, potentially leading to data exfiltration, system compromise, or deployment of ransomware.

## Impact

Successful exploitation of this vulnerability allows attackers to execute arbitrary commands on the affected Weaver E-cology 10.0 server. This can lead to full system compromise, data exfiltration, and disruption of services. Given the critical nature of systems often managed by E-cology, this could have significant business impact, leading to financial losses, reputational damage, and legal liabilities. There is currently no public information on the number of victims or specific sectors targeted.

## Recommendation

*   Upgrade all Weaver E-cology 10.0 installations to a version equal to or greater than 20260312 to patch CVE-2026-22679.
*   Deploy the Sigma rule "Detect Weaver E-cology Dubbo API Exploitation Attempt" to detect exploitation attempts targeting the vulnerable endpoint.
*   Monitor web server logs for POST requests to the `/papi/esearch/data/devops/dubboApi/debug/method` endpoint with suspicious `interfaceName` and `methodName` parameters (see logsource details in the Sigma rule).
