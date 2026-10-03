---
title: Mautic Server-Side Template Injection (SSTI) RCE (CVE-2026-9558)
slug: 2026-07-mautic-ssti
description: A Server-Side Template Injection (SSTI) vulnerability in Mautic's theme engine allows authenticated users with theme creation or upload privileges to execute arbitrary system commands (Remote Code Execution) and access restricted system files on the hosting server, due to the platform rendering uploaded Twig templates without a sandbox or strict function restrictions.
date: "2026-07-03T10:08:26Z"
lastmod: "2026-10-03T04:55:46Z"
type: advisory
types:
  - advisory
severities:
  - critical
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=D8B2CA95-8503-530A-9FFE-AFDE0D1C0C1A&utm_source=rss&utm_medium=rss
tags:
  - server-side-template-injection
  - rce
  - mautic
  - web-application
  - cve-2026-9558
vendors:
  - Mautic
products:
  - Mautic 4.x
  - Mautic 5.x
  - Mautic 6.x
  - Mautic 7.x
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An authenticated user with theme upload and creation privileges can bypass boundaries to execute arbitrary system commands on the hosting server (Remote Code Execution)
    confidence_band: high
cves:
  - id: CVE-2026-9558
    cvss: 9.9
    epss: 0.00789
references:
  - https://github.com/advisories/GHSA-9fx4-7cmj-47vg
  - https://sploitus.com/exploit?id=D8B2CA95-8503-530A-9FFE-AFDE0D1C0C1A&utm_source=rss&utm_medium=rss
updates:
  - at: "2026-10-03T04:55:46Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=D8B2CA95-8503-530A-9FFE-AFDE0D1C0C1A&utm_source=rss&utm_medium=rss
---

Mautic, an open-source marketing automation platform, is affected by a critical Server-Side Template Injection (SSTI) vulnerability, tracked as CVE-2026-9558, within its theme engine. This flaw stems from Mautic rendering uploaded Twig templates without a sandbox or strict function restrictions, allowing authenticated users with permissions to create or upload themes to bypass security boundaries. This vulnerability enables remote code execution (RCE) on the hosting server, permitting attackers to execute arbitrary system commands and access restricted system files or configuration settings. The issue has been addressed in Mautic versions 7.1.2, 6.0.9, 5.2.11, and for 4.x via ELTS in version 4.4.20. Organizations using affected versions are urged to upgrade immediately to prevent exploitation.

## Attack Chain

1.  **Initial Access**: An authenticated user with existing "create or upload themes" permissions (core:themes:create) logs into the Mautic application.
2.  **Payload Crafting**: The authenticated user crafts a malicious Twig template designed to leverage server-side template injection (SSTI), embedding commands for arbitrary code execution (e.g., `{{ _self.env.execute('cat /etc/passwd') }}`).
3.  **Malicious Theme Upload**: The user utilizes their authorized permissions to either upload a new theme package containing the crafted malicious Twig template or directly creates a theme with the injected template content.
4.  **Template Processing**: The Mautic application processes and renders the newly uploaded or created theme and its components, which includes the malicious Twig template.
5.  **Arbitrary Code Execution**: As the vulnerable Twig template is rendered without a sandbox, the embedded SSTI payload is evaluated by the server-side template engine, resulting in the execution of arbitrary commands or scripts on the underlying operating system.
6.  **Impact**: The attacker achieves Remote Code Execution (RCE) on the Mautic server, gaining the ability to exfiltrate sensitive data, modify system files, establish persistence, or perform further lateral movement within the network.

## Impact

A successful exploitation of CVE-2026-9558 grants an authenticated attacker with theme management privileges the ability to execute arbitrary commands on the Mautic hosting server. This leads to Remote Code Execution (RCE), allowing access to sensitive data, system files, and configuration settings. Such an attack could result in complete compromise of the Mautic instance, unauthorized data exfiltration, service disruption, or serve as a beachhead for further attacks within the organization's infrastructure. There are no concrete numbers on victims or specific sectors targeted mentioned, but any organization utilizing vulnerable Mautic versions is at risk.

## Recommendation

*   Upgrade Mautic instances to patched versions 7.1.2, 6.0.9, 5.2.11, or 4.4.20 (for 4.x via ELTS) immediately to mitigate CVE-2026-9558.
*   Restrict theme upload and creation permissions (`core:themes:create`) to only highly trusted administrators to minimize the attack surface for CVE-2026-9558.
*   Monitor web server access logs for unusual HTTP POST requests to theme-related endpoints, especially those containing potentially malicious template syntax.
