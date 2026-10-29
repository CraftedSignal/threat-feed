---
brief_id: brief-2026-10-29-kaspersky-dos
event_id: brief-2026-10-29-kaspersky-dos
revision: 1
activity_at: "2026-10-29T18:34:29Z"
title: Kaspersky Network Agent and Security Center Denial of Service (CVE-2026-88941)
slug: 2026-10-kaspersky-dos
description: A denial of service vulnerability in Kaspersky Network Agent and Security Center Administration Server modules allows an attacker to disrupt service availability (CVE-2026-88941).
date: "2026-10-29T18:34:29Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Patch management verification required for affected products.
tags:
  - vulnerability
  - dos
  - patch-management
vendors:
  - Kaspersky
products:
  - Network Agent (< 10.5.0.1781)
  - Network Agent (< 14.0.0.20145)
  - Network Agent (< 17.0.0.3992)
  - Kaspersky Next Expert View Network Agent (< 16.2.0.1547)
  - Kaspersky Next Pro View Network Agent (< 15.1.0.22268)
  - Kaspersky Security Center Administration Server (< 15.1.0.28509)
affected_os:
  - Windows XP SP2
  - Windows XP SP3
  - Windows
cves:
  - id: CVE-2026-88941
    cvss: 5.2
    epss: 0.00144
    kev_status: "false"
references:
  - https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1417/
  - https://support.kaspersky.com/vulnerability/list-of-advisories/12430#291026
  - https://www.cve.org/CVERecord?id=CVE-2026-88941
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Kaspersky Security Center and Network Agent instances to the versions specified in advisory 12430#291026
      owner: IT Operations
      due: 48h
      evidence: Kaspersky security advisory 12430#291026
  mitigation_plan:
    - priority: immediate
      action: Upgrade Kaspersky modules to the minimum versions listed in the Overview section
      owner: IT Operations
      addresses: CVE-2026-88941
      evidence: Kaspersky security advisory 12430#291026
---

A denial of service vulnerability exists in multiple versions of the Kaspersky Network Agent and Security Center Administration Server. Successful exploitation of CVE-2026-88941 allows an attacker to disrupt the functionality of the affected modules. Kaspersky has issued security advisory 12430#291026 with remediation instructions and required patches.

## Impact

Successful exploitation results in a denial of service, impacting the availability of the Kaspersky security management infrastructure.

## Recommendation

Identify and patch all instances of the affected Kaspersky software modules immediately. Refer to Kaspersky security advisory 12430#291026 for specific update instructions for the following versions:
- Kaspersky Network Agent for Windows XP SP2 (< 10.5.0.1781)
- Kaspersky Network Agent for Windows XP SP3 (< 14.0.0.20145)
- Kaspersky Network Agent for Windows (< 17.0.0.3992)
- Kaspersky Next Expert View Network Agent (< 16.2.0.1547)
- Kaspersky Next Pro View Network Agent (< 15.1.0.22268)
- Kaspersky Security Center Administration Server for Windows (< 15.1.0.28509, Update 3)
