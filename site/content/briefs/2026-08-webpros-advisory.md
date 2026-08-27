---
title: Security Vulnerabilities in Plesk Management Interface and Extensions
slug: 2026-08-webpros-advisory
description: WebPros has released security updates for Plesk and its Migrator and Site Import extensions to address critical vulnerabilities CVE-2026-65642 and CVE-2026-65647.
date: "2026-08-27T15:11:15Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - vulnerability
  - patch-management
  - web-hosting
vendors:
  - WebPros
products:
  - Plesk
  - Plesk Migrator
  - Plesk Site Import
cves:
  - id: CVE-2026-65642
    epss: 0.00427
  - id: CVE-2026-65647
    epss: 0.00458
references:
  - https://cyber.gc.ca/en/alerts-advisories/webpros-security-advisory-av26-854
  - https://support.plesk.com/hc/en-us/articles/42844242102679-Vulnerability-CVE-2026-65642-in-Plesk-s-database-management-interface
  - https://support.plesk.com/hc/en-us/articles/42871001389207-Vulnerability-CVE-2026-65647-in-Plesk-s-Site-Import-and-Migrator-extensions
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Patch Plesk and associated extensions to the versions specified in the advisory.
      owner: IT Operations
      due: 48h
      evidence: Source advisory AV26-854
---

WebPros has issued a security advisory (AV26-854) identifying vulnerabilities impacting its flagship Plesk hosting management platform and several associated extensions. The flaws include CVE-2026-65642, which affects the Plesk database management interface, and CVE-2026-65647, which affects the Plesk Site Import and Plesk Migrator extensions. These vulnerabilities present risks to server security and database administration workflows. WebPros has released patched versions for Plesk (versions 18.0.79.8, 18.0.80.4, and later), Plesk Migrator (version 2.36.0 and later), and Plesk Site Import (version 1.12.1 and later). Administrators are encouraged to prioritize these updates to mitigate the risk of unauthorized database access or exploit attempts targeting the affected management extensions.

## Impact

Successful exploitation of these vulnerabilities could result in unauthorized access, data exposure, or administrative disruption within the Plesk environment. Given that Plesk is widely utilized by hosting providers and site administrators to manage complex server configurations, these vulnerabilities could enable attackers to gain control over hosted databases or leverage administrative extension functions to impact multiple sites on a shared server.

## Recommendation

* Apply the security patches for Plesk by upgrading to version 18.0.79.8 or 18.0.80.4 immediately.
* Update the Plesk Migrator extension to at least version 2.36.0.
* Update the Plesk Site Import extension to at least version 1.12.1.
* Audit administrative access logs for unusual activity targeting the Plesk database management interface or extension execution logs following the update.
