---
brief_id: brief-2026-10-30-apple-xcode-vulnerabilities
event_id: brief-2026-10-30-apple-xcode-vulnerabilities
revision: 1
activity_at: "2026-10-30T21:19:06Z"
title: 'Apple Xcode: Multiple data confidentiality vulnerabilities (CVE-2026-112602, CVE-2026-112605)'
slug: 2026-10-apple-xcode-vulnerabilities
description: Multiple vulnerabilities in Apple Xcode versions prior to 27.2 could allow an attacker to compromise data confidentiality.
date: "2026-10-30T21:19:06Z"
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
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Verified against CERT-FR and Apple security bulletin 149589
cpes:
  - cpe:2.3:a:apple:xcode:*:*:*:*:*:*:*:*
vendors:
  - Apple
products:
  - Xcode (< 27.2)
cves:
  - id: CVE-2026-112602
    epss: 0.00136
    kev_status: "false"
  - id: CVE-2026-112605
    epss: 0.00136
    kev_status: "false"
references:
  - https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1421/
  - https://support.apple.com/en-us/149589
  - https://www.cve.org/CVERecord?id=CVE-2026-112602
  - https://www.cve.org/CVERecord?id=CVE-2026-112605
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade all instances of Xcode to version 27.2 or later
      owner: IT Operations
      addresses: CVE-2026-112602, CVE-2026-112605
      evidence: Apple security bulletin 149589
---

Apple has released security updates to address multiple vulnerabilities in Xcode, specifically affecting versions prior to 27.2. These flaws, identified as CVE-2026-112602 and CVE-2026-112605, may allow an attacker to gain unauthorized access to sensitive information. No specific exploit details or delivery mechanisms were provided in the advisory.

## Impact

The identified vulnerabilities present a risk to data confidentiality. The specific scope of information accessible depends on the nature of the underlying flaws within the Xcode environment.

## Recommendation

* Inventory all systems running Xcode and update to version 27.2 or later immediately to mitigate CVE-2026-112602 and CVE-2026-112605.
* Audit developer environments for unauthorized access or anomalous activity following the application of the security update.
