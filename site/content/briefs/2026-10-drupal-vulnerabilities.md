---
title: Multiple Vulnerabilities in Drupal Core
slug: 2026-10-drupal-vulnerabilities
description: Multiple vulnerabilities, including remote code execution and cross-site scripting, affect Drupal versions 10.6.x, 11.3.x, and 11.4.x, requiring immediate patching to prevent unauthorized code execution.
date: "2026-10-15T16:26:25Z"
lastmod: "2026-10-19T16:19:05Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Drupal
products:
  - Drupal (10.6.x < 10.6.19)
  - Drupal (11.3.x < 11.3.19)
  - Drupal (11.4.x < 11.4.10)
cves:
  - id: CVE-2026-108099
  - id: CVE-2026-108097
  - id: CVE-2026-108515
  - id: CVE-2026-108514
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1321/
  - https://drupal.org/sa-core-2026-014
  - https://drupal.org/sa-core-2026-015
  - https://drupal.org/sa-core-2026-016
  - https://www.cve.org/CVERecord?id=CVE-2026-108097
  - https://www.cve.org/CVERecord?id=CVE-2026-108514
  - https://www.cve.org/CVERecord?id=CVE-2026-108515
  - https://www.securityweek.com/drupal-warns-of-fast-exploitation-risk-for-critical-core-rce-flaw/
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade Drupal to versions 10.6.19, 11.3.19, or 11.4.10 respectively
      owner: IT Operations
      addresses: CVE-2026-108097, CVE-2026-108514, CVE-2026-108515
      evidence: Source provides specific fixed versions for all affected branches
updates:
  - at: "2026-10-19T16:19:05Z"
    level: L2
    summary: added CVE-2026-108097 +3
    sources:
      - securityweek
    source_urls:
      - https://www.securityweek.com/drupal-warns-of-fast-exploitation-risk-for-critical-core-rce-flaw/
---

The French National Cybersecurity Agency (ANSSI) has issued an advisory regarding multiple critical vulnerabilities discovered in the Drupal content management system. These vulnerabilities, documented in security bulletins SA-CORE-2026-014, SA-CORE-2026-015, and SA-CORE-2026-016, expose affected instances to remote code execution (RCE) and reflected cross-site scripting (XSS) attacks. 

The scope includes Drupal versions 10.6.x before 10.6.19, 11.3.x before 11.3.19, and 11.4.x before 11.4.10. CVEs identified for these issues include CVE-2026-108097, CVE-2026-108514, and CVE-2026-108515. Given the potential for unauthenticated remote code execution, organizations deploying Drupal must verify their current version and apply the vendor-provided patches immediately to mitigate the risk of system compromise.

## Impact

Successful exploitation of these vulnerabilities could result in full site compromise through remote code execution, potentially leading to unauthorized data exfiltration, lateral movement within the network, or the injection of malicious scripts into user sessions via XSS. The number of affected instances is potentially high given the prevalence of Drupal in enterprise content management environments.

## Recommendation

* Prioritize the update of all Drupal instances to the latest secure versions as identified in the referenced security bulletins (SA-CORE-2026-014, SA-CORE-2026-015, and SA-CORE-2026-016).
* Upgrade Drupal 10.6.x instances to 10.6.19 or later.
* Upgrade Drupal 11.3.x instances to 11.3.19 or later.
* Upgrade Drupal 11.4.x instances to 11.4.10 or later.
* Monitor web application firewall logs for unusual HTTP POST requests or suspicious parameters that may indicate attempts to exploit RCE or XSS vectors targeting the core Drupal endpoints.
