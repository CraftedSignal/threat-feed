---
brief_id: brief-2026-10-27-git-annex-data-exfiltration
event_id: brief-2026-10-27-git-annex-data-exfiltration
revision: 1
activity_at: "2026-10-27T21:53:40Z"
title: 'git-annex: Cross-repository data exfiltration (CVE-2026-112818)'
slug: 2026-10-git-annex-data-exfiltration
description: A security vulnerability in git-annex (CVE-2026-112818) allows for unauthorized cross-repository data exfiltration, requiring an update to version 10.20261026 or the application of backported patches.
date: "2026-10-27T21:53:40Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
tags:
  - exfiltration
  - vulnerability
  - git-annex
products:
  - git-annex (< 10.20261026)
cves:
  - id: CVE-2026-112818
    kev_status: unknown
references:
  - https://seclists.org/oss-sec/2026/q4/394
  - https://git-annex.branchable.com/download/
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  mitigation_plan:
    - priority: immediate
      action: Upgrade git-annex to version 10.20261026 or apply backported patches
      owner: IT Operations
      addresses: CVE-2026-112818
      evidence: I have released git-annex 10.20261026, which fixes a cross-repository data exfiltration attack.
---

git-annex versions prior to 10.20261026 are vulnerable to a cross-repository data exfiltration flaw, tracked as CVE-2026-112818. This vulnerability allows for unauthorized access or leakage of data between managed repositories. The maintainer has released a patched version and provided backported patches for previous releases to address the risk.

## Impact

Successful exploitation allows for the unauthorized exfiltration of data across repositories managed by git-annex, potentially leading to the exposure of sensitive information stored in those environments.

## Recommendation

* Upgrade git-annex to version 10.20261026 or apply the available backported patches provided by the maintainer for older versions.
* Inventory systems utilizing git-annex to identify versions requiring the security update.
