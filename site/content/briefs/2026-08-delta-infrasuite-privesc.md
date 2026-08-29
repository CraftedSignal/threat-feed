---
title: Privilege Escalation Vulnerability in Delta Electronics Infrasuite Device Master
slug: 2026-08-delta-infrasuite-privesc
description: CVE-2023-30765 is a privilege escalation vulnerability in Delta Electronics Infrasuite Device Master versions prior to 1.0.7 that allows an attacker to add arbitrary users to the administrator group.
date: "2026-08-29T14:45:56Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:deltaww:infrasuite_device_master:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - ics
  - cve-2023-30765
vendors:
  - Delta Electronics
products:
  - Infrasuite Device Master (< 1.0.7)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Privilege escalation in Delta Electronics Infrasuite Device Master adds user to admins group.
    confidence_band: high
cves:
  - id: CVE-2023-30765
    cvss: 8.8
    epss: 0.01967
references:
  - https://www.zerodayinitiative.com/advisories/ZDI-23-905/
  - https://www.cisa.gov/news-events/ics-advisories/icsa-23-180-01
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-0XFML-CVE-2023-30765
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Delta Electronics Infrasuite Device Master to 1.0.7 or later.
      owner: IT Operations
      due: 48h
      evidence: Source documentation identifies 1.0.7 as the fixed version for CVE-2023-30765.
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to management interfaces.
      owner: IT Operations
      addresses: CVE-2023-30765
      evidence: Vulnerability allows remote privilege escalation.
---

Delta Electronics Infrasuite Device Master versions prior to 1.0.7 are susceptible to a privilege escalation vulnerability tracked as CVE-2023-30765 (ZDI-23-905). This vulnerability allows an authenticated attacker to perform an unauthorized modification of user group memberships, specifically enabling the escalation of a standard user account to the administrator group. The discovery of this flaw, attributed to Piotr Bazydlo, highlights a critical security gap in access control management within the Infrasuite Device Master platform. The availability of a public functional exploit script on repository platforms as of August 2026 significantly increases the likelihood of exploitation attempts against unpatched infrastructure. Security teams should prioritize patching instances to version 1.0.7 or higher to mitigate unauthorized administrative access.

## Impact

Successful exploitation of CVE-2023-30765 allows an attacker to gain full administrative control over the targeted Delta Electronics Infrasuite Device Master instance. This leads to complete system compromise, unauthorized access to sensitive operational data, and potential manipulation of integrated facility management hardware. Given the product's role in infrastructure management, impact includes potential disruption to critical facility services.

## Recommendation

Prioritize the upgrade of all internet-facing Delta Electronics Infrasuite Device Master instances to version 1.0.7 or later. Restrict network access to the web management interface, ensuring it is not exposed to the public internet. Audit existing administrator groups for unauthorized users added through non-standard account creation processes. Monitor web server logs for suspicious POST requests targeting user management endpoints consistent with the documented exploit tool usage.
