---
brief_id: brief-2026-10-27-samtools-vulnerabilities
event_id: brief-2026-10-27-samtools-vulnerabilities
revision: 1
activity_at: "2026-10-27T21:53:28Z"
title: 'Samtools: Multiple security vulnerabilities'
slug: 2026-10-samtools-vulnerabilities
description: Multiple security vulnerabilities have been identified and addressed in samtools versions 1.24 and earlier, with patches now available in release 1.25 and backported versions.
date: "2026-10-27T21:53:28Z"
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
  validation_status: No technical exploitation details available to validate
tags:
  - vulnerability
  - software-update
  - informational
vendors:
  - samtools
products:
  - samtools (<= 1.24)
references:
  - https://seclists.org/oss-sec/2026/q4/404
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade samtools to version 1.25 or apply backported versions 1.24.1, 1.23.3, 1.22.4, or 1.21.3
      owner: IT Operations
      addresses: All instances of samtools <= 1.24
      evidence: Multiple vulnerabilities, listed below, have been disclosed in the samtools package. These have all been fixed in a new release 1.25 and have also been pack-ported to versions 1.24.1, 1.23.3, 1.22.4 and 1.21.3
---

Multiple vulnerabilities have been disclosed in the samtools package. The maintainers have released version 1.25 to address these issues. Backported fixes are also available in versions 1.24.1, 1.23.3, 1.22.4, and 1.21.3. CVE identifiers have not yet been assigned by the CVE naming authority and will be updated on the project's GitHub page upon assignment.

## Recommendation

* Inventory all systems running samtools to identify versions 1.24 and earlier.
* Update samtools to version 1.25, or apply the relevant backported version (1.24.1, 1.23.3, 1.22.4, or 1.21.3) appropriate for your environment.
