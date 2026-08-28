---
title: Unauthenticated OS Command Injection in Vitec Flamingo
slug: 2026-07-vitec-flamingo-rce
description: Vitec Flamingo version 4.12.2 contains an unauthenticated OS command injection vulnerability (CVE-2026-60121) in the `admin/ajax/ping.php` endpoint, allowing remote attackers to execute arbitrary commands with root privileges via a double-evaluation flaw in shell argument handling through the `host` POST parameter.
date: "2026-07-13T14:17:52Z"
lastmod: "2026-08-28T17:16:32Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:vitec:flamingo:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-HORKIMHAB-CVE-2026-60121-CVE-2026-61498&utm_source=rss&utm_medium=rss
tags:
  - os-command-injection
  - rce
  - web-application
  - linux
vendors:
  - Vitec
products:
  - Flamingo 4.12.2
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: remote attackers to execute arbitrary commands by exploiting a double-evaluation flaw in shell argument handling
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: allows injected commands to execute with root privileges via passwordless sudo.
    confidence_band: high
cves:
  - id: CVE-2026-60121
    cvss: 9.8
    epss: 0.02336
  - id: CVE-2026-61498
    cvss: 9.8
    epss: 0.04089
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-60121
  - https://nvd.nist.gov/vuln/detail/CVE-2026-61498
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-HORKIMHAB-CVE-2026-60121-CVE-2026-61498&utm_source=rss&utm_medium=rss
rules:
  - title: Detects CVE-2026-60121 Exploitation - Flamingo RCE
    description: Detects CVE-2026-60121 exploitation - HTTP POST requests to admin/ajax/ping.php with shell metacharacters in parameters, indicating OS command injection attempt.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
      - privilege_escalation
    techniques:
      - T1059.006
      - T1068
      - T1190
    data_sources:
      - webserver
rules_count: 1
updates:
  - at: "2026-07-13T14:18:20Z"
    level: L2
    summary: added CVE-2026-61498
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-61498
  - at: "2026-08-28T17:16:32Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-HORKIMHAB-CVE-2026-60121-CVE-2026-61498&utm_source=rss&utm_medium=rss
---

A critical unauthenticated OS command injection vulnerability, tracked as CVE-2026-60121, has been identified in Vitec Flamingo version 4.12.2. This flaw exists within the `admin/ajax/ping.php` endpoint and stems from a double-evaluation issue in the handling of shell arguments. Remote attackers can exploit this by manipulating the `host` POST parameter with crafted shell metacharacters. Although `escapeshellarg()` is initially applied, an internal system wrapper retrieves the *decoded* value from `argv` and uses it in a subsequent `shell_exec()` call without proper escaping, leading to arbitrary command execution with root privileges through passwordless sudo. This allows for complete system compromise without prior authentication, posing a severe risk to organizations using vulnerable Vitec Flamingo instances.

## Attack Chain

1. An unauthenticated remote attacker sends an HTTP POST request to the `admin/ajax/ping.php` endpoint of a vulnerable Vitec Flamingo instance.
2. The attacker includes a maliciously crafted `host` POST parameter containing shell metacharacters (e.g., `127.0.0.1;id`).
3. The application applies `escapeshellarg()` to the `host` parameter, seemingly neutralizing the injection attempt.
4. An internal system wrapper, designed to execute network `ping` commands, retrieves the *decoded* value of the `host` parameter directly from its `argv` (argument vector).
5. The wrapper then incorporates this decoded, unescaped value into a second, internal `shell_exec()` call without applying further sanitization.
6. The injected shell commands (e.g., `id` or other arbitrary commands) are executed on the underlying operating system.
7. The executed commands inherit privileges, and due to system configuration (e.g., passwordless `sudo` for the `ping` command's execution context), they run with root privileges.
8. The attacker achieves arbitrary OS command execution with root privileges, leading to full system compromise, data exfiltration, or further lateral movement.

## Impact

Successful exploitation of CVE-2026-60121 results in unauthenticated remote code execution with root privileges on the affected Vitec Flamingo server. This critical vulnerability allows attackers to gain complete control over the system, potentially leading to unauthorized data access, modification, or destruction, installation of persistent backdoors, and use of the compromised server as a pivot point for further attacks within the network. Organizations running vulnerable versions face severe risks including critical data breaches, significant operational disruption, and reputational damage.

## Recommendation

* Patch CVE-2026-60121 immediately by upgrading Vitec Flamingo to a version beyond 4.12.2 or applying any vendor-provided security patches.
* Deploy the `Detects CVE-2026-60121 Exploitation - Flamingo RCE` Sigma rule to your SIEM to detect exploitation attempts against the `admin/ajax/ping.php` endpoint.
* Monitor webserver logs for HTTP POST requests to `/admin/ajax/ping.php` containing unusual or shell-like characters in the query string or request body.
