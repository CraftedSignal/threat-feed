---
brief_id: brief-2026-10-27-mozilla-firefox-vulns
event_id: brief-2026-10-27-mozilla-firefox-vulns
revision: 1
activity_at: "2026-10-27T17:39:20Z"
title: 'Mozilla Firefox: Multiple vulnerabilities in Firefox for iOS (CVE-2026-116631, CVE-2026-116632)'
slug: 2026-10-mozilla-firefox-vulns
description: Multiple vulnerabilities in Firefox for iOS versions prior to 156.1, detailed in MFSA2026-117, allow for data integrity compromise and security policy bypass.
date: "2026-10-27T17:39:20Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Awaiting organizational device inventory check
cpes:
  - cpe:2.3:a:mozilla:firefox:*:*:*:*:*:iphone_os:*:*
tags:
  - vulnerability
  - browser
vendors:
  - Mozilla
products:
  - Firefox for iOS (< 156.1)
affected_os:
  - iOS
cves:
  - id: CVE-2026-116631
    kev_status: unknown
  - id: CVE-2026-116632
    kev_status: unknown
references:
  - https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1391/
  - https://www.mozilla.org/en-US/security/advisories/mfsa2026-117/
  - https://www.cve.org/CVERecord?id=CVE-2026-116631
  - https://www.cve.org/CVERecord?id=CVE-2026-116632
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Firefox for iOS to version 156.1 or later
      owner: IT Operations
      due: 48h
      evidence: Mozilla Security Advisory MFSA2026-117
  mitigation_plan:
    - priority: immediate
      action: Upgrade to Firefox for iOS 156.1
      owner: IT Operations
      addresses: CVE-2026-116631, CVE-2026-116632
      evidence: Mozilla Security Advisory MFSA2026-117
---

Multiple vulnerabilities have been identified in Mozilla Firefox for iOS versions prior to 156.1. These flaws, documented in Mozilla Security Advisory MFSA2026-117, can be leveraged to achieve data integrity compromise and bypass security policy enforcement. No specific in-the-wild exploitation has been publicly confirmed as of the reporting date.

## Impact

Successful exploitation could result in the compromise of browser data integrity and the bypass of established security policies, potentially leading to unauthorized access or modification of sensitive information processed by the browser.

## Recommendation

* Inventory all mobile devices within the organization utilizing Firefox for iOS.
* Upgrade Firefox for iOS to version 156.1 or later immediately to address CVE-2026-116631 and CVE-2026-116632.
* Consult the Mozilla Security Advisory MFSA2026-117 for detailed remediation steps and technical depth.
