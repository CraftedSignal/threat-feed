---
title: GoClaw OS Command Injection Vulnerability (CVE-2026-10219)
slug: 2026-06-goclaw-cmd-injection
description: nextlevelbuilder GoClaw up to 3.11.3 is vulnerable to remote OS command injection via manipulation of the write_file Tool component's FsBridge.WriteFile function (CVE-2026-10219), with a public exploit available.
date: "2026-06-01T04:17:42Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - command-injection
  - vulnerability
  - webserver
vendors:
  - nextlevelbuilder
products:
  - GoClaw <= 3.11.3
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-10219
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-10219
  - https://github.com/nextlevelbuilder/goclaw/
  - https://github.com/nextlevelbuilder/goclaw/issues/1121
  - https://github.com/nextlevelbuilder/goclaw/pull/1155
  - https://vuldb.com/cve/CVE-2026-10219
  - https://vuldb.com/submit/821939
  - https://vuldb.com/vuln/367498
  - https://vuldb.com/vuln/367498/cti
rules:
  - title: Detects CVE-2026-10219 Exploitation Attempt - GoClaw Command Injection
    description: Detects CVE-2026-10219 exploitation attempt - HTTP request containing shell metacharacters to GoClaw, indicative of command injection vulnerability.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detects CVE-2026-10219 Exploitation - GoClaw suspicious POST request
    description: Detects CVE-2026-10219 exploitation attempt - HTTP POST request containing shell metacharacters to GoClaw, indicative of command injection vulnerability.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

nextlevelbuilder GoClaw, a tool up to version 3.11.3, contains an OS command injection vulnerability in the `FsBridge.WriteFile` function within the `internal/sandbox/fsbridge.go` file, which is part of the `write_file` tool component. This vulnerability (CVE-2026-10219) allows remote attackers to inject and execute arbitrary operating system commands by manipulating input to the affected function. Publicly available exploits exist, increasing the risk of exploitation. While a pull request has been submitted to address this vulnerability, it is still awaiting acceptance. Defenders should prioritize detection and mitigation measures to prevent potential compromise.

## Attack Chain

1.  An attacker identifies a GoClaw instance running a vulnerable version (<= 3.11.3).
2.  The attacker crafts a malicious request targeting the `FsBridge.WriteFile` function of the `write_file` tool.
3.  The malicious request includes specially crafted input designed to inject OS commands.
4.  The `FsBridge.WriteFile` function fails to properly sanitize the attacker-controlled input.
5.  The vulnerable function executes the injected OS commands on the server.
6.  The attacker gains arbitrary code execution on the GoClaw server.
7.  The attacker can then perform actions such as installing malware, accessing sensitive data, or pivoting to other systems on the network.

## Impact

Successful exploitation of this vulnerability could allow an attacker to execute arbitrary commands on the GoClaw server, potentially leading to complete system compromise. The attacker could gain unauthorized access to sensitive data, disrupt services, or use the compromised system as a launchpad for further attacks within the network. The severity is heightened by the existence of a public exploit, increasing the likelihood of exploitation.

## Recommendation

*   Deploy the Sigma rule to detect potential exploitation attempts targeting the `FsBridge.WriteFile` function.
*   Monitor web server logs for suspicious requests containing shell metacharacters indicative of command injection attacks.
*   Apply any available patches or updates for GoClaw to address the vulnerability once the pull request is accepted.
*   Implement input validation and sanitization measures to prevent command injection vulnerabilities.
*   Review and harden the configuration of GoClaw instances to minimize the attack surface.
