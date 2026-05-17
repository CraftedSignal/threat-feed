---
title: GitBucket 4.23.1 Unauthenticated Remote Code Execution Vulnerability (CVE-2018-25332)
slug: 2026-05-gitbucket-rce
description: GitBucket 4.23.1 contains an unauthenticated remote code execution vulnerability (CVE-2018-25332) allowing attackers to execute arbitrary commands by exploiting weak secret token generation and insecure file upload functionality via a malicious JAR plugin.
date: "2026-05-17T13:17:30Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - cve
  - rce
  - gitbucket
  - unauthenticated
vendors:
  - VulnCheck
products:
  - GitBucket 4.23.1
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2018-25332
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25332
  - https://github.com/gitbucket/gitbucket
  - https://security.szurek.pl/
  - https://www.exploit-db.com/exploits/44668
  - https://www.vulncheck.com/advisories/gitbucket-unauthenticated-remote-code-execution
rules:
  - title: Detect CVE-2018-25332 GitBucket Malicious JAR Upload
    description: Detects CVE-2018-25332 exploitation —  Attempts to upload malicious JAR plugins via the git-lfs endpoint in GitBucket
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2018-25332 GitBucket Exploit Endpoint Access
    description: Detects CVE-2018-25332 exploitation — Access to an exposed exploit endpoint after JAR upload in GitBucket.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059
    data_sources:
      - webserver
rules_count: 2
---

GitBucket version 4.23.1 is vulnerable to an unauthenticated remote code execution flaw. This vulnerability, identified as CVE-2018-25332, allows remote attackers to execute arbitrary commands on the server. The attack involves exploiting weak secret token generation, which leads to a brute-forceable Blowfish encryption key. Attackers leverage this to upload a malicious JAR plugin through the git-lfs endpoint, subsequently triggering execution of system commands through a specially crafted endpoint. This vulnerability poses a significant risk as it allows for complete system compromise without requiring any prior authentication.

## Attack Chain

1.  Attacker identifies a GitBucket 4.23.1 instance exposed to the internet.
2.  Attacker exploits the weak secret token generation to brute-force the Blowfish encryption key.
3.  Attacker crafts a malicious JAR plugin containing code for remote command execution.
4.  Attacker uses the git-lfs endpoint to upload the malicious JAR plugin to the GitBucket instance.
5.  Attacker triggers the installation or activation of the uploaded JAR plugin.
6.  Attacker crafts a request to the exposed exploit endpoint to execute arbitrary system commands.
7.  The GitBucket server executes the attacker-supplied system commands.
8.  Attacker achieves remote code execution, potentially leading to full system compromise and data exfiltration.

## Impact

Successful exploitation of CVE-2018-25332 allows an unauthenticated attacker to execute arbitrary commands on the affected GitBucket server. This can lead to full system compromise, data breaches, and potential disruption of services. The vulnerability has a CVSS v3.1 score of 9.8, indicating a critical severity. The impact includes complete compromise of confidentiality, integrity, and availability of the affected system.

## Recommendation

*   Upgrade GitBucket to a version higher than 4.23.1 to patch CVE-2018-25332.
*   Deploy the Sigma rule "Detect CVE-2018-25332 GitBucket Malicious JAR Upload" to detect attempts to upload malicious JAR plugins.
*   Monitor web server logs for requests to the git-lfs endpoint associated with suspicious JAR file uploads, as covered by the Sigma rule "Detect CVE-2018-25332 GitBucket Exploit Endpoint Access".
*   Implement strong authentication and authorization mechanisms to prevent unauthenticated access and file uploads.
