---
title: ImpressCMS 1.4.2 Remote Code Execution via Autotasks Interface (CVE-2021-47938)
slug: 2026-05-impresscms-rce
description: ImpressCMS 1.4.2 is vulnerable to remote code execution (RCE) via the autotasks administrative interface, where authenticated attackers can inject malicious PHP code into the sat_code parameter via a POST request to /modules/system/admin.php, leading to arbitrary PHP code execution through GET parameters (CVE-2021-47938).
date: "2026-05-10T13:20:36Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - code-injection
  - rce
  - impresscms
vendors:
  - ImpressCMS
products:
  - ImpressCMS 1.4.2
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
  - id: CVE-2021-47938
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2021-47938
  - https://www.exploit-db.com/exploits/50298
  - https://www.impresscms.org/
  - https://www.impresscms.org/modules/downloads/
  - https://www.vulncheck.com/advisories/impresscms-remote-code-execution-via-autotasks
rules:
  - title: Detects CVE-2021-47938 Exploitation — ImpressCMS Autotasks RCE Attempt
    description: Detects CVE-2021-47938 exploitation — HTTP POST requests to /modules/system/admin.php with suspicious PHP code injection attempts in the sat_code parameter
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detects CVE-2021-47938 Exploitation — ImpressCMS Autotasks RCE Webshell Access
    description: Detects CVE-2021-47938 exploitation — HTTP GET requests accessing potential webshell file created via sat_code
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1505
    data_sources:
      - webserver
rules_count: 2
---

ImpressCMS 1.4.2 is susceptible to a remote code execution vulnerability, identified as CVE-2021-47938, within the autotasks administrative interface. This flaw allows authenticated attackers to inject arbitrary PHP code by manipulating the `sat_code` parameter. Successful exploitation allows attackers to execute arbitrary PHP commands on the targeted system, potentially leading to full system compromise. This vulnerability requires authentication, limiting the scope of potential attackers to those with valid credentials or those who can bypass authentication mechanisms. Defenders need to ensure proper input validation and access controls to prevent unauthorized code injection.

## Attack Chain

1.  Attacker authenticates to the ImpressCMS application.
2.  Attacker crafts a malicious POST request targeting `/modules/system/admin.php?fct=autotasks&op=mod`.
3.  The POST request includes the `sat_code` parameter containing malicious PHP code.
4.  The application improperly processes the `sat_code` parameter, leading to code injection.
5.  The injected code creates an executable file on the server.
6.  The attacker triggers execution of the created file via a GET request.
7.  Arbitrary PHP code is executed on the server.
8.  The attacker achieves remote code execution, potentially leading to further compromise of the system.

## Impact

Successful exploitation of CVE-2021-47938 allows attackers to execute arbitrary PHP code on the ImpressCMS server. This can lead to complete compromise of the application and the underlying system, including data theft, website defacement, or further propagation of attacks within the network. Given the high CVSS score of 8.8, this vulnerability poses a significant risk to organizations using the affected version of ImpressCMS.

## Recommendation

*   Apply appropriate input validation and sanitization to all user-supplied data, especially the `sat_code` parameter, to prevent code injection (CVE-2021-47938).
*   Implement the Sigma rule provided to detect malicious POST requests to `/modules/system/admin.php` with suspicious content in the `sat_code` parameter.
*   Ensure that the ImpressCMS application is running with least privilege to limit the impact of successful code execution.
