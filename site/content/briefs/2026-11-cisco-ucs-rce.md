---
brief_id: brief-2026-11-05-cisco-ucs-rce
event_id: brief-2026-11-05-cisco-ucs-rce
revision: 1
activity_at: "2026-11-05T01:30:14Z"
title: Cisco Unified Computing System Central Software Remote Code Execution Vulnerability
slug: 2026-11-cisco-ucs-rce
description: Cisco addressed a remote code execution vulnerability in Cisco Unified Computing System (UCS) Central Software affecting versions prior to 2.1(2c).
date: "2026-11-05T01:30:14Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
vendors:
  - Cisco
products:
  - Unified Computing System (UCS) Central Software (< 2.1(2c))
references:
  - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cucs-rce-LzHSFRDQ
  - https://cyber.gc.ca/en/alerts-advisories/cisco-security-advisory-av26-1127
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade Cisco UCS Central Software to version 2.1(2c) or later.
      owner: IT Operations
      addresses: Cisco UCS Central Software RCE vulnerability
      evidence: Cisco security advisory recommending updates for versions prior to 2.1(2c).
---

Cisco has released a security advisory addressing a remote code execution (RCE) vulnerability in Cisco Unified Computing System (UCS) Central Software. The vulnerability affects installations running software versions prior to 2.1(2c). No further technical details or exploit code were provided in the initial security advisory at the time of publication.

## Recommendation

* Inventory all instances of Cisco UCS Central Software within the environment.
* Upgrade Cisco UCS Central Software to version 2.1(2c) or later to remediate the identified vulnerability.
* Review the official Cisco security advisory for further updates or configuration workarounds.
