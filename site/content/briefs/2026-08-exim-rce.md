---
title: Critical Remote Code Execution Vulnerability in Exim MTA
slug: 2026-08-exim-rce
description: Exim is affected by a critical vulnerability (CVE-2024-39929) that allows a remote, unauthenticated attacker to execute arbitrary code via a logic error in header field processing.
date: "2026-08-14T14:08:20Z"
lastmod: "2026-08-29T16:46:40Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:exim:exim:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-RXERIUM-CVE-2024-39929&utm_source=rss&utm_medium=rss
tags:
  - vulnerability
  - remote-code-execution
  - mail-server
vendors:
  - Exim
products:
  - Exim
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Ein entfernter, anonymer Angreifer kann eine Schwachstelle in Exim ausnutzen, um beliebigen Programmcode auszuführen.
    confidence_band: high
cves:
  - id: CVE-2024-39929
    cvss: 5.4
    epss: 0.41225
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-1505
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-39929
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-RXERIUM-CVE-2024-39929&utm_source=rss&utm_medium=rss
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch all Exim instances to the latest available version addressing CVE-2024-39929.
      owner: IT Operations
      due: 24h
      evidence: Critical severity vulnerability in Exim MTA identified by BSI.
  mitigation_plan:
    - priority: immediate
      action: Restrict external access to SMTP ports using firewall rules.
      owner: IT Operations
      addresses: CVE-2024-39929
      evidence: Remote unauthenticated exploitation vector.
updates:
  - at: "2026-08-29T16:46:40Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-RXERIUM-CVE-2024-39929&utm_source=rss&utm_medium=rss
---

The BSI has released a security advisory regarding a critical vulnerability affecting the Exim mail transfer agent (MTA). This vulnerability allows a remote, unauthenticated attacker to achieve remote code execution (RCE) on target systems. The flaw stems from a logic error encountered during the processing of specific header fields within incoming email traffic. 

Exim is a widely deployed open-source MTA on Unix-like operating systems. Because the vulnerability is exploitable by an unauthenticated remote actor via standard SMTP communication, it poses a severe risk to any internet-facing mail server. Defenders should identify all instances of Exim in their environment and prioritize patching to the latest version provided by their distribution maintainers. The vulnerability is tracked as CVE-2024-39929.

## Impact

Successful exploitation of this vulnerability permits an unauthenticated attacker to execute arbitrary code with the privileges of the Exim process. This can lead to full system compromise, data exfiltration, and the establishment of persistent backdoors on the affected mail server. Given the nature of MTAs, compromised servers could also be leveraged for large-scale phishing campaigns or as relays for further network exploitation within an organization.

## Recommendation

- Identify all instances of Exim running in the production environment by auditing process lists and service configurations.
- Apply security patches for CVE-2024-39929 immediately once provided by the official Exim maintainers or OS package repositories.
- Restrict access to SMTP services (port 25, 587) to only known, authorized IP addresses via host-based or network firewalls to reduce the attack surface.
- Review mail server logs for anomalous header content or unexpected child process execution spawned by the Exim service user.
