---
title: Critical Vulnerabilities in Plesk and cPanel/WHM
slug: 2026-09-webpros-vulnerabilities
description: Multiple vulnerabilities, including arbitrary code execution as root, impact various WebPros products including Plesk extensions and cPanel/WHM components.
date: "2026-09-24T19:51:55Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - web-hosting
  - critical-patch
vendors:
  - WebPros
products:
  - Plesk (18.0.34 to 18.0.81.0)
  - Plesk RESTful API (2.4.2 to 2.4.6)
  - Site Import (<= 1.12.1)
  - WP Toolkit for cPanel (<= 6.11.2-10794)
  - cPanel/WHM (11.134.0.57, 11.136.0.41, 11.138.0.8)
cves:
  - id: CVE-2026-68492
  - id: CVE-2026-87898
  - id: CVE-2026-87899
  - id: CVE-2026-87900
references:
  - https://cyber.gc.ca/en/alerts-advisories/webpros-security-advisory-av26-961
  - https://support.plesk.com/hc/en-us/articles/43644058632983-Vulnerability-CVE-2026-68492-Arbitrary-code-execution-as-root-in-Plesk-via-the-Plesk-RESTful-API-extension
  - https://support.plesk.com/hc/en-us/articles/43641151026583-Vulnerability-CVE-2026-87898-Arbitrary-code-execution-as-root-in-Plesk-s-Site-Import-extension
  - https://support.cpanel.net/hc/en-us/articles/43591715125271-Security-CVE-2026-87899-Vulnerability-in-cPanel-s-CalDAV-CardDAV-September-22-2026
  - https://support.cpanel.net/hc/en-us/articles/43597969409943-Security-CVE-2026-87900-Vulnerability-in-WP-Toolkit-Database-Creation-September-22-2026
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Plesk to 18.0.80.8 or later
      owner: IT Operations
      due: 24h
      evidence: Vendor security advisories linked in the reference section.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Plesk to 18.0.80.8 or later
      owner: IT Operations
      addresses: CVE-2026-68492, CVE-2026-87898, CVE-2026-87899, CVE-2026-87900
      evidence: AV26-961
---

WebPros has issued security advisories regarding critical vulnerabilities affecting several of its core hosting management products, including Plesk, its associated extensions, and cPanel/WHM. As of September 23, 2026, researchers and the vendor identified flaws leading to arbitrary code execution (ACE) with root-level privileges. 

Specific vulnerabilities include CVE-2026-68492 and CVE-2026-87898, which provide root-level ACE via the 'Plesk RESTful API' and 'Site Import' extensions, respectively. Additionally, cPanel/WHM is impacted by CVE-2026-87899, affecting CalDAV/CardDAV functionality, and CVE-2026-87900, involving improper database creation processes within the WP Toolkit. Given the high-privilege nature of these vulnerabilities and their potential for full system compromise, administrators are urged to verify current versions against the patched releases provided by the vendor.

## Impact

Successful exploitation of these vulnerabilities allows an unauthenticated or low-privileged attacker to achieve arbitrary code execution as the root user. This provides full control over the compromised web hosting server, facilitating sensitive data exfiltration, service disruption, and persistence through the installation of backdoors. These vulnerabilities impact a broad range of hosting environments, specifically those utilizing Plesk and cPanel/WHM control panels.

## Recommendation

Prioritized actions for administrators include immediate auditing and patching of affected server infrastructure.
- Patch Plesk instances to versions beyond 18.0.81.0 immediately.
- Update 'Plesk RESTful API' extension beyond version 2.4.6.
- Update 'Site Import' extension to versions beyond 1.12.1.
- Update 'WP Toolkit for cPanel' beyond version 6.11.2-10794.
- Update cPanel/WHM to the latest secure versions (11.134.0.57, 11.136.0.41, or 11.138.0.8 depending on the release branch).
