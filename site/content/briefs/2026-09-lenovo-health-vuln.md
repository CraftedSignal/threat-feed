---
title: Critical Vulnerability in Lenovo Health Android Application
slug: 2026-09-lenovo-health-vuln
description: A high-severity vulnerability in the Lenovo Health Android application, exclusively distributed in the Chinese market, allows unauthorized access to sensitive user health data.
date: "2026-09-10T23:09:27Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:lenovo:health:*:*:*:*:*:android:*:*
vendors:
  - Lenovo
products:
  - Lenovo Health Android Application
affected_os:
  - Android
cves:
  - id: CVE-2026-75940
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75940
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory and identify instances of Lenovo Health Android Application across mobile device fleets.
      owner: IT Operations
      due: 48h
      evidence: Source NVD identification of affected software.
  mitigation_plan:
    - priority: immediate
      action: Restrict or remove the Lenovo Health Android application until a manufacturer-provided update is applied.
      owner: IT Operations
      addresses: CVE-2026-75940
      evidence: NVD vulnerability alert.
---

A critical security vulnerability has been identified in the Lenovo Health Android application, which is distributed exclusively within the Chinese market. This security flaw, tracked as CVE-2026-75940, carries a CVSS v3.1 base score of 9.1, indicating a severe risk to data confidentiality. The vulnerability allows an unauthorized actor to bypass existing security controls and access sensitive health-related information stored or processed by the application. Because the application is regional, its impact is limited to users within China who have installed the software. Defenders should note that while no specific exploitation chain was provided by the National Vulnerability Database (NVD), the high severity and potential for data exfiltration mandate prompt investigation for unauthorized data access attempts within environments where this application is in use.

## Impact

The vulnerability poses a severe risk to the privacy of users of the Lenovo Health Android application. Successful exploitation could result in the unauthorized disclosure and exfiltration of sensitive health records, potentially impacting a large user base within the Chinese market.

## Recommendation

Prioritize inventory management to identify all instances of the Lenovo Health Android application in mobile device management (MDM) solutions. Since the application is restricted to the Chinese market, verify if it is present on any corporate-managed mobile devices within your organization. If identified, restrict the application's network access or remove it until a patch is confirmed and applied. Monitor mobile device logs for any abnormal data access patterns or unauthorized requests originating from the Lenovo Health application package name.
