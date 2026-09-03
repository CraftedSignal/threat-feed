---
title: Remote Code Execution Vulnerability in CUPS
slug: 2026-08-cups-rce
description: A vulnerability in the cups-browsed service allows a local attacker to achieve arbitrary code execution via malicious print queue discovery packets.
date: "2026-08-12T16:45:30Z"
lastmod: "2026-09-03T01:48:22Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:openprinting:cups-browsed:2.0.1:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-TONYARRIS-CVE-2024-47176-SCANNER&utm_source=rss&utm_medium=rss
tags:
  - vulnerability
  - rce
  - linux
vendors:
  - OpenPrinting
products:
  - CUPS
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: A vulnerability in the Common Unix Printing System (CUPS) allows a local attacker to execute arbitrary code.
    confidence_band: high
cves:
  - id: CVE-2024-47176
    cvss: 5.3
    epss: 0.50605
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2791
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-TONYARRIS-CVE-2024-47176-SCANNER&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Patch CVE-2024-47176
      owner: IT Operations
      addresses: CVE-2024-47176
      evidence: Source advisory
updates:
  - at: "2026-09-03T01:48:22Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-TONYARRIS-CVE-2024-47176-SCANNER&utm_source=rss&utm_medium=rss
---

The Common Unix Printing System (CUPS) is affected by a security flaw, identified as CVE-2024-47176, which resides in the cups-browsed service. This service is responsible for discovering printers on a network. The vulnerability arises from improper handling of packet data received during the printer discovery process. A local attacker can craft malicious discovery packets that, when processed by cups-browsed, lead to the execution of arbitrary commands on the host system. Given that cups-browsed often runs with elevated privileges, this flaw poses a significant risk for privilege escalation and system compromise on affected Linux systems. Defenders should prioritize patching the CUPS stack and reviewing the necessity of the cups-browsed service in their environment.

## Impact

Successful exploitation allows a local attacker to execute arbitrary code with the privileges of the cups-browsed service. This can lead to full system compromise, unauthorized data access, and persistence on the affected machine. This vulnerability affects Linux systems where CUPS and the associated cups-browsed service are deployed, potentially impacting enterprise workstations, servers, and embedded devices that utilize standard Linux printing configurations.

## Recommendation

- Update the CUPS package to the latest version provided by your Linux distribution maintainer to address CVE-2024-47176.
- Disable the cups-browsed service if network printer discovery is not required for the system function.
- Review network configurations to restrict access to CUPS discovery ports if the service must remain enabled.
