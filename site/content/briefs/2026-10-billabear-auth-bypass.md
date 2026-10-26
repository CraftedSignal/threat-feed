---
brief_id: brief-2026-10-26-billabear-auth-bypass
event_id: brief-2026-10-26-billabear-auth-bypass
revision: 1
activity_at: "2026-10-26T11:41:47Z"
title: 'BillaBear: Installation handler missing authentication (CVE-2026-116257)'
slug: 2026-10-billabear-auth-bypass
description: A vulnerability in the BillaBear Installation Handler (up to 2025.01.03) causes missing authentication within the processInstall function.
date: "2026-10-26T11:41:47Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
products:
  - BillaBear (up to 2025.01.03)
cves:
  - id: CVE-2026-116257
    cvss: 7.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116257
---

CVE-2026-116257 identifies a missing authentication vulnerability in BillaBear versions up to 2025.01.03. The issue exists in the `processInstall` function of `src/BillaBear/Controller/InstallController.php` within the Installation Handler component. Remote exploitation is possible, and the exploit has been publicly disclosed. The vendor was contacted but did not provide a response. The vulnerability has a CVSS v3.1 base score of 7.3.
