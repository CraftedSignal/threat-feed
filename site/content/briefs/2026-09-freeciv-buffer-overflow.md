---
title: Heap Buffer Overflow in Freeciv worklist_load
slug: 2026-09-freeciv-buffer-overflow
description: Freeciv versions prior to 3.2.6 contain a heap-based buffer overflow in the worklist_load() function that allows memory corruption via maliciously crafted savegame files.
date: "2026-09-12T19:21:30Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:freeciv:freeciv:*:*:*:*:*:*:*:*
vendors:
  - Freeciv
products:
  - Freeciv (< 3.2.6)
cves:
  - id: CVE-2026-90556
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90556
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade Freeciv to version 3.2.6 or later
      owner: IT Operations
      addresses: CVE-2026-90556
      evidence: NVD advisory identifies version 3.2.6 as the fixed version.
---

Freeciv versions before 3.2.6 are susceptible to a heap buffer overflow vulnerability located in the worklist_load() function. The vulnerability arises from improper validation of worklist lengths when the application parses savegame files. Specifically, the game software defines a fixed array limit of 64 elements for the worklist. An attacker can create a crafted savegame file that declares a worklist length exceeding this threshold. When the Freeciv engine processes this file, the subsequent memory write operation bypasses the fixed array boundary, allowing data to be written into adjacent heap-allocated struct fields. This memory corruption can occur during the standard process of loading a savegame file, potentially impacting both end-user clients and dedicated server instances that ingest untrusted game data.

## Impact

Successful exploitation of this vulnerability results in heap memory corruption, which can lead to application crashes (Denial of Service) or potentially arbitrary code execution depending on the state of the heap at the time of the overflow. The vulnerability affects any user or infrastructure relying on Freeciv for game hosting that processes savegame files from potentially malicious sources.

## Recommendation

* Upgrade all Freeciv instances to version 3.2.6 or later immediately to apply the patch for CVE-2026-90556.
* Restrict the ability to load savegame files to trusted sources or known-good environments until the update is applied.
