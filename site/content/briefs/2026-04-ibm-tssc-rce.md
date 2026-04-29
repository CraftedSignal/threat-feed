---
title: IBM Total Storage Service Console (TSSC) / TS4500 IMC Unauthenticated Remote Command Execution
slug: 2026-04-ibm-tssc-rce
description: An unauthenticated user can execute arbitrary commands with normal user privileges on vulnerable IBM Total Storage Service Console (TSSC) / TS4500 IMC versions due to improper validation of user-supplied input, as identified by CVE-2026-5935.
date: "2026-04-23T00:16:46Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - cve-2026-5935
  - rce
  - command injection
vendors:
  - IBM
products:
  - Total Storage Service Console
  - TS4500 IMC
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
cves:
  - id: CVE-2026-5935
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5935
  - https://www.ibm.com/support/pages/node/7270127
rules:
  - title: Detect Exploitation Attempts CVE-2026-5935
    description: Detects potential exploitation attempts of CVE-2026-5935 based on suspicious HTTP requests.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
      - linux
  - title: Detect TSSC/IMC Command Injection via POST Request
    description: Detects command injection attempts targeting TSSC/IMC via POST requests with suspicious parameters.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-5935 describes a critical vulnerability affecting IBM Total Storage Service Console (TSSC) / TS4500 IMC software. Specifically, versions 9.2, 9.3, 9.4, 9.5, and 9.6 are susceptible to unauthenticated remote command execution. The vulnerability stems from insufficient validation of user-supplied input, allowing an attacker to inject and execute arbitrary commands on the system. Successful exploitation grants the attacker normal user privileges. This vulnerability poses a significant risk as it allows attackers to compromise the system without authentication, potentially leading to data breaches, system disruption, or further lateral movement within the network. Defenders should prioritize patching or mitigating this vulnerability.

## Attack Chain

1.  An unauthenticated attacker identifies a vulnerable IBM Total Storage Service Console (TSSC) / TS4500 IMC instance running versions 9.2, 9.3, 9.4, 9.5, or 9.6.
2.  The attacker crafts a malicious request containing an OS command injection payload. This payload is designed to exploit the improper input validation within the TSSC/IMC software.
3.  The attacker sends the crafted request to the vulnerable TSSC/IMC instance, targeting a specific endpoint or function susceptible to command injection.
4.  The TSSC/IMC software processes the request without proper validation, passing the malicious payload to the underlying operating system.
5.  The operating system executes the injected command with the privileges of a normal user account.
6.  The attacker gains the ability to execute arbitrary commands on the system, potentially allowing them to read sensitive files, modify configurations, or install malicious software.
7.  The attacker may leverage their initial access to escalate privileges, move laterally within the network, or establish persistent access to the compromised system.

## Impact

Successful exploitation of CVE-2026-5935 allows an unauthenticated attacker to execute arbitrary commands on the affected IBM Total Storage Service Console (TSSC) / TS4500 IMC system. This can lead to complete system compromise, data breaches, and disruption of services. The impact could range from unauthorized access to sensitive data to the deployment of ransomware, depending on the attacker's objectives and the level of access achieved after exploitation. Due to the lack of authentication requirement, the vulnerability is highly critical.

## Recommendation

*   Apply the patch or upgrade to a fixed version of IBM Total Storage Service Console (TSSC) / TS4500 IMC as outlined in the IBM advisory ([https://www.ibm.com/support/pages/node/7270127](https://www.ibm.com/support/pages/node/7270127)).
*   Deploy the Sigma rule to detect command execution via web requests targeting TSSC/IMC.
*   Implement network segmentation to limit the blast radius of a potential compromise of the TSSC/IMC system.
