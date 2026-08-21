---
title: 'CVE-2026-58455: Dockwatch Unauthenticated OS Command Injection'
slug: 2026-07-dockwatch-os-command-injection
description: Remote attackers can exploit an unauthenticated OS command injection vulnerability (CVE-2026-58455) in Dockwatch versions up to 0.6.567, arising from a missing exit() after an authentication redirect in loader.php combined with unsanitized input passed to shell_exec() in ajax/compose.php, to execute arbitrary shell commands leading to full host compromise, especially in deployments where the Docker socket is mounted.
date: "2026-07-02T16:25:32Z"
lastmod: "2026-08-21T18:38:51Z"
type: advisory
types:
  - advisory
severities:
  - critical
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=95C7431E-4F72-576F-BC08-274AD2697E6D&utm_source=rss&utm_medium=rss
tags:
  - vulnerability
  - rce
  - web-application
  - linux
vendors:
  - Notifiarr
products:
  - Dockwatch <= 0.6.567
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Dockwatch through 0.6.567 contains an unauthenticated OS command injection vulnerability that allows remote attackers to execute arbitrary shell commands by exploiting a missing exit() after an authentication redirect in loader.php
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: unsanitized input passed to shell_exec() in ajax/compose.php. Attackers can...inject arbitrary commands via the composePath POST parameter in the composePull action to achieve full host compromise
    confidence_band: high
cves:
  - id: CVE-2026-58455
    cvss: 9.8
    epss: 0.04856
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-58455
  - https://sploitus.com/exploit?id=95C7431E-4F72-576F-BC08-274AD2697E6D&utm_source=rss&utm_medium=rss
rules:
  - title: Detects CVE-2026-58455 Exploitation — Dockwatch Unauthenticated OS Command Injection
    description: Detects CVE-2026-58455 exploitation — HTTP POST to /ajax/compose.php with shell metacharacters in the composePath parameter, indicating an OS command injection attempt in Dockwatch.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.004
      - T1190
    data_sources:
      - webserver
rules_count: 1
updates:
  - at: "2026-08-21T18:38:51Z"
    level: L2
    summary: poc_available; added CVE-2026-58455
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=95C7431E-4F72-576F-BC08-274AD2697E6D&utm_source=rss&utm_medium=rss
---

A critical unauthenticated OS command injection vulnerability, tracked as CVE-2026-58455, affects Dockwatch versions through 0.6.567. This flaw stems from a critical oversight where `loader.php` fails to exit after an incomplete authentication redirect, allowing attackers to "seed" a necessary session flag. Subsequently, unsanitized user input passed to the `shell_exec()` function within `ajax/compose.php` can be leveraged for arbitrary command execution. Attackers can inject malicious shell commands via the `composePath` POST parameter during the `composePull` action. This vulnerability leads to full host compromise, a severe risk for organizations using Dockwatch, particularly if the standard deployment includes mounting the Docker socket, which could facilitate container escapes or further system access. Defenders must patch immediately to prevent exploitation.

## Attack Chain

1.  **Incomplete Authentication Bypass**: An unauthenticated attacker initiates a request to `loader.php` to exploit a missing `exit()` after an authentication redirect, allowing them to seed a required session flag.
2.  **Crafted HTTP POST Request**: The attacker then sends a specially crafted HTTP POST request to the `/ajax/compose.php` endpoint of the vulnerable Dockwatch instance.
3.  **Command Injection Payload**: This POST request includes the `composePath` parameter, which contains unsanitized arbitrary shell commands (e.g., `composePath=;id;` or `composePath=;cat /etc/passwd;`).
4.  **Remote Command Execution**: The Dockwatch application processes the `composePath` parameter and, due to a lack of proper input sanitization, passes the attacker-controlled input directly to the `shell_exec()` function.
5.  **Host Compromise**: The injected shell commands are executed on the underlying operating system with the privileges of the Dockwatch process, granting the attacker control over the host.
6.  **Privilege Escalation/Lateral Movement**: If the Docker socket is mounted (a common deployment scenario for container management tools), the executed commands can interact with the Docker daemon, potentially enabling container escape, privilege escalation, or lateral movement within the host or network.
7.  **Impact Achieved**: Full host compromise is achieved, enabling data exfiltration, deployment of further malicious payloads (e.g., ransomware, backdoors), or continued attack activities.

## Impact

The successful exploitation of CVE-2026-58455 results in full host compromise, allowing unauthenticated remote attackers to execute arbitrary operating system commands. This provides attackers complete control over the compromised Dockwatch server, enabling them to steal sensitive data, deploy ransomware or other malicious software, establish persistent access, or pivot to other systems within the network. If the Docker socket is mounted, attackers can manipulate containers, potentially escaping to the host system or accessing containerized applications and data. The high CVSS v3.1 Base Score of 9.8 reflects the critical nature of this vulnerability.

## Recommendation

*   Immediately patch Dockwatch to a version beyond 0.6.567 to remediate CVE-2026-58455.
*   Deploy the Sigma rule provided in this brief to your SIEM to detect attempts at exploiting CVE-2026-58455.
*   Enable comprehensive web server logging for all Dockwatch instances, specifically capturing `cs-method`, `cs-uri-stem`, `cs-uri-query`, and `sc-status` to facilitate detection of exploitation attempts.
*   Review web server access logs for any suspicious POST requests to `/ajax/compose.php` containing shell metacharacters in the `composePath` query parameter as described in the attack chain.
