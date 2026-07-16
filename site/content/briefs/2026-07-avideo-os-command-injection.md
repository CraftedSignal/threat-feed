---
title: AVideo OS Command Injection Vulnerability (CVE-2026-63305)
slug: 2026-07-avideo-os-command-injection
description: AVideo versions through 29.0 contain an OS command injection vulnerability, CVE-2026-63305, in the ffmpeg.json.php endpoint where unescaped notifyCode and callback parameters can be exploited by attackers crafting encrypted payloads to execute arbitrary OS commands as the web-server user, potentially leading to full system compromise.
date: "2026-07-16T13:21:41Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - os-command-injection
  - web-application
  - cve
vendors:
  - WWBN
products:
  - AVideo
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: AVideo through 29.0 contains an OS command injection vulnerability in the ffmpeg.json.php endpoint... Attackers who can craft a valid encrypted payload can inject arbitrary shell metacharacters into these fields to execute OS commands as the web-server user.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: inject arbitrary shell metacharacters into these fields to execute OS commands as the web-server user.
    confidence_band: high
cves:
  - id: CVE-2026-63305
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-63305
  - https://github.com/WWBN/AVideo/security/advisories/GHSA-g9x9-q7qj-6mv5
  - https://www.vulncheck.com/advisories/avideo-through-os-command-injection-via-ffmpeg-json-php
iocs:
  - type: url
    value: https://github.com/WWBN/AVideo/security/advisories/GHSA-g9x9-q7qj-6mv5
  - type: url
    value: https://www.vulncheck.com/advisories/avideo-through-os-command-injection-via-ffmpeg-json-php
ioc_counts:
  url: 2
rules:
  - title: Detects CVE-2026-63305 Exploitation - OS Command Injection via ffmpeg.json.php
    description: Detects CVE-2026-63305 exploitation attempts by identifying HTTP POST requests to the ffmpeg.json.php endpoint with shell metacharacters in the cs-uri-query field, indicative of OS command injection.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

CVE-2026-63305 details a critical OS command injection vulnerability affecting AVideo versions through 29.0. This flaw resides within the `ffmpeg.json.php` endpoint, where input parameters `notifyCode` and `callback` are inadequately sanitized before being concatenated into a shell command. Attackers can leverage this by crafting a valid, encrypted payload containing shell metacharacters. When processed by the vulnerable AVideo instance, these metacharacters bypass security controls, allowing the attacker to inject and execute arbitrary operating system commands with the privileges of the web-server user. This vulnerability presents a significant risk, enabling potential server compromise, data exfiltration, or further lateral movement within an affected environment. There is no information about specific threat actors or observed exploitation in the wild, but the nature of the vulnerability makes it highly attractive for attackers.

## Attack Chain

1. Attacker identifies an AVideo instance running a vulnerable version (through 29.0).
2. Attacker crafts a malicious payload, embedding shell metacharacters (e.g., `;`, `|`, `&&`, `$(`) into the `notifyCode` or `callback` parameters.
3. The crafted payload is then encrypted according to AVideo's expected cryptographic format.
4. Attacker sends an HTTP POST request to the `/ffmpeg.json.php` endpoint on the target AVideo server, including the encrypted malicious payload.
5. The AVideo application processes the incoming request, decrypts the payload, and attempts to integrate the `notifyCode` or `callback` values into an internal OS command.
6. Due to the improper neutralization of special elements in the `ffmpeg.json.php` endpoint, the injected shell metacharacters are not escaped, leading to the execution of the attacker's arbitrary command.
7. The operating system executes the attacker-supplied command with the privileges of the web-server user.
8. This results in arbitrary OS command execution on the AVideo server, allowing the attacker to potentially compromise the system, exfiltrate data, or establish persistence.

## Impact

Successful exploitation of CVE-2026-63305 allows for arbitrary OS command execution on the AVideo server. This level of access grants the attacker the ability to completely compromise the web server, potentially leading to unauthorized access to sensitive data, modification or deletion of content, defacement of the application, or the deployment of additional malicious software. Attackers can leverage this access to establish persistence, pivot to other systems within the network, or use the compromised server as a platform for further attacks. The extent of the damage depends on the privileges of the web-server user and the network segmentation of the affected system.

## Recommendation

* Patch AVideo installations immediately to a version greater than 29.0 to remediate CVE-2026-63305.
* Deploy the "Detects CVE-2026-63305 Exploitation - OS Command Injection via ffmpeg.json.php" Sigma rule to your SIEM to identify exploitation attempts.
* Ensure web server access logs are enabled and centrally collected, especially for HTTP POST requests to the `/ffmpeg.json.php` path, to enable detection of suspicious activity flagged by the rule.
