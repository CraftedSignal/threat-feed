---
title: Evolution CMS Authenticated Remote Code Execution via Module Creation (CVE-2021-47939)
slug: 2026-05-evolution-cms-rce
description: Evolution CMS version 3.1.6 is vulnerable to remote code execution, where authenticated users with module creation permissions can inject PHP code into module parameters, allowing them to execute arbitrary system commands by sending POST requests to '/manager/index.php' with malicious PHP code in the 'post' parameter to create modules that execute arbitrary commands when invoked, as tracked by CVE-2021-47939.
date: "2026-05-10T13:20:49Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve
  - cve-2021-47939
  - rce
  - code-injection
vendors:
  - Evolution CMS
products:
  - Evolution CMS 3.1.6
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server-Side Code Injection
cves:
  - id: CVE-2021-47939
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2021-47939
  - https://evo.im/
  - https://github.com/evolution-cms/evolution/releases
  - https://www.exploit-db.com/exploits/50296
  - https://www.vulncheck.com/advisories/evolution-cms-authenticated-remote-code-execution-via-module-creation
rules:
  - title: Detect CVE-2021-47939 Exploitation Attempt via Malicious POST Request
    description: Detects CVE-2021-47939 exploitation — Identifies POST requests to /manager/index.php with PHP code in the 'post' parameter, indicating a code injection attempt.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1505.003
    data_sources:
      - webserver
  - title: Detect CVE-2021-47939 Exploitation Attempt via system() call
    description: Detects CVE-2021-47939 exploitation — Identifies POST requests to /manager/index.php with PHP code containing system() function call.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1505.003
    data_sources:
      - webserver
rules_count: 2
---

Evolution CMS 3.1.6 is susceptible to a remote code execution (RCE) vulnerability, CVE-2021-47939. This flaw allows authenticated users who possess module creation privileges to inject arbitrary PHP code into module parameters. Successful exploitation enables attackers to execute system-level commands on the underlying server. The vulnerability stems from insufficient input validation during module creation, making it possible to inject and execute malicious PHP code through crafted POST requests. This poses a significant risk to organizations using Evolution CMS, potentially leading to full system compromise.

## Attack Chain

1.  An attacker gains valid credentials for an Evolution CMS account with module creation permissions.
2.  The attacker crafts a POST request targeting `/manager/index.php`.
3.  The POST request includes malicious PHP code within the `post` parameter, designed to create a module.
4.  The injected PHP code is crafted to execute arbitrary system commands.
5.  The attacker submits the malicious POST request to create the module.
6.  The newly created module, containing the injected PHP code, is saved on the server.
7.  The attacker invokes the newly created module, triggering the execution of the injected PHP code.
8.  The server executes the injected PHP code, allowing the attacker to run arbitrary system commands, potentially leading to complete system compromise.

## Impact

Successful exploitation of CVE-2021-47939 allows an attacker to execute arbitrary system commands on the Evolution CMS server. This can lead to complete compromise of the system, including data theft, modification, or destruction. The attacker can potentially gain access to sensitive information, install malware, or use the compromised server as a staging ground for further attacks within the network. Given the high CVSS score of 8.8, this vulnerability poses a significant risk to organizations using affected versions of Evolution CMS.

## Recommendation

*   Apply available patches or upgrade to a secure version of Evolution CMS to remediate CVE-2021-47939.
*   Deploy the Sigma rule "Detect CVE-2021-47939 Exploitation Attempt via Malicious POST Request" to identify exploitation attempts based on the injection of PHP code in POST requests.
*   Implement strict input validation and sanitization measures to prevent code injection vulnerabilities in web applications.
*   Monitor web server logs for suspicious POST requests to `/manager/index.php` containing PHP code within the `post` parameter using the log source "webserver".
