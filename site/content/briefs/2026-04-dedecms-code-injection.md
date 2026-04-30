---
title: DedeCMS 5.7.118 Code Injection Vulnerability via Crafted Module Upload (CVE-2026-30643)
slug: 2026-04-dedecms-code-injection
description: DedeCMS 5.7.118 is vulnerable to remote code execution via crafted setup tag values during a module upload, as exploited by an unauthenticated attacker (CVE-2026-30643).
date: "2026-04-01T17:28:39Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - dedecms
  - code-injection
  - cve-2026-30643
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server-Side Component
cves:
  - id: CVE-2026-30643
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-30643
  - https://gist.github.com/0psPwn/10c43912adee9bfe2ff4fec947d4ee5a
  - https://www.dedecms.com/
rules:
  - title: Detect DedeCMS Module Upload Code Injection
    description: Detects potential code injection attempts during DedeCMS module uploads by identifying suspicious parameters in HTTP POST requests.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1189
      - T1505.003
    data_sources:
      - webserver
      - linux
  - title: Detect DedeCMS Webshell Uploads
    description: Detects potential webshell uploads by identifying suspicious filenames being uploaded during module installation.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1505.003
    data_sources:
      - webserver
      - linux
rules_count: 2
---

DedeCMS version 5.7.118 is susceptible to a critical code injection vulnerability (CVE-2026-30643) that allows unauthenticated attackers to execute arbitrary code on the server. The vulnerability stems from improper handling of setup tag values during module uploads. Successful exploitation of this flaw enables threat actors to compromise the web server, potentially leading to data breaches, system takeover, and further malicious activities. This vulnerability requires immediate attention from organizations using DedeCMS 5.7.118. The vulnerability was reported to MITRE on April 1, 2026.

## Attack Chain

1. An attacker identifies a DedeCMS 5.7.118 instance accessible over the internet.
2. The attacker crafts a malicious module package containing a specially crafted setup tag within its configuration files.
3. The attacker uploads the malicious module package to the DedeCMS instance.
4. During the module installation process, the DedeCMS application parses the module's configuration files, including the malicious setup tag.
5. Due to insufficient input validation, the crafted setup tag injects arbitrary code into the application's execution context.
6. The injected code is executed by the web server, granting the attacker control over the system.
7. The attacker can then use this initial foothold to execute system commands.
8. The attacker establishes persistence and moves laterally within the network.

## Impact

Successful exploitation of CVE-2026-30643 allows unauthenticated attackers to execute arbitrary code on the target system. This could lead to complete system compromise, data theft, defacement of the website, or further propagation of malware within the network. Given the severity and ease of exploitation, any DedeCMS 5.7.118 instance exposed to the internet is at high risk. Unpatched systems are vulnerable to complete takeover.

## Recommendation

*   Upgrade DedeCMS to a patched version that addresses CVE-2026-30643.
*   Implement strict input validation on all user-supplied data, especially during module uploads, to prevent code injection.
*   Deploy the provided Sigma rule `Detect DedeCMS Module Upload Code Injection` to identify exploitation attempts.
*   Monitor web server logs (category: webserver) for suspicious activity related to module installation and unusual requests.
*   Apply the CWE-94 mitigations to prevent code injection at the application level.
