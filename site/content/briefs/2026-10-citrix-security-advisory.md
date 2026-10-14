---
title: Critical Vulnerabilities in Citrix UniconOS and XenServer
slug: 2026-10-citrix-security-advisory
description: Citrix has released security bulletins addressing multiple vulnerabilities across UniconOS and XenServer products, including CVE-2026-53562, CVE-2026-53563, CVE-2026-53564, CVE-2026-79610, CVE-2026-102700, and CVE-2026-102701.
date: "2026-10-13T23:44:25Z"
lastmod: "2026-10-14T16:24:05Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - citrix
  - patch-management
vendors:
  - Citrix
products:
  - UniconOS (< 2603 LTSR CU2)
  - UniconOS (< 2607.2 CR)
  - XenServer (8.4)
  - XenServer (9)
  - UniconOS (< 2607.2)
cves:
  - id: CVE-2026-53562
  - id: CVE-2026-53563
  - id: CVE-2026-53564
  - id: CVE-2026-79610
  - id: CVE-2026-102700
references:
  - https://cyber.gc.ca/en/alerts-advisories/citrix-security-advisory-av26-1034
  - https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX697187
  - https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX697170
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3928
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Patch UniconOS to 2607.2 or later
      owner: IT Operations
      due: 48h
      evidence: Citrix security bulletin guidance
  mitigation_plan:
    - priority: immediate
      action: Upgrade UniconOS to 2607.2 or later
      owner: IT Operations
      addresses: CVE-2026-53562, CVE-2026-53563, CVE-2026-53564, CVE-2026-79610, CVE-2026-102700, CVE-2026-102701
      evidence: Vendor security bulletins
updates:
  - at: "2026-10-14T16:24:05Z"
    level: L2
    summary: added CVE-2026-79610
    sources:
      - bsi
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3928
---

Citrix has issued security advisories regarding multiple vulnerabilities affecting UniconOS and XenServer product lines. The affected UniconOS versions include those prior to 2603 LTSR CU2 and 2607.2 CR. The XenServer product is affected in versions 8.4 and 9. These vulnerabilities, identified as CVE-2026-53562, CVE-2026-53563, CVE-2026-53564, CVE-2026-79610, CVE-2026-102700, and CVE-2026-102701, require immediate attention from administrators. The Cyber Centre (CCCS) recommends that organizations review the specific vendor bulletins provided by Citrix and apply available security updates to mitigate potential exposure. As these vulnerabilities represent potential entry points for unauthorized access or system compromise within enterprise infrastructure, prompt patching is essential to maintain the security posture of affected Citrix environments.

## Impact

Successful exploitation of these vulnerabilities could lead to significant security compromises, including unauthorized system access, potential privilege escalation, or service disruption within the targeted Citrix environments. These products are critical infrastructure components in many enterprise settings; failure to remediate these vulnerabilities leaves organizational networks vulnerable to exploitation. The number of potentially impacted systems is substantial, given the widespread use of Citrix solutions for virtualized application and desktop delivery.

## Recommendation

* Review the Citrix Security Bulletins for detailed vulnerability information and remediation steps: CTX697187 and CTX697170.
* Update UniconOS environments to at least 2603 LTSR CU2 or 2607.2 CR immediately.
* Apply security updates for XenServer versions 8.4 and 9 as provided by the vendor.
* Monitor Citrix administrative and management logs for unauthorized access patterns following the application of patches.
