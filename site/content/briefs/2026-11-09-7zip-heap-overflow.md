---
brief_id: brief-2026-11-10-7zip-heap-overflow
event_id: brief-2026-11-10-7zip-heap-overflow
revision: 1
activity_at: "2026-11-10T14:33:35Z"
title: '7-Zip: LZX decoder heap out-of-bounds write (CVE-2026-125742)'
slug: 2026-11-09-7zip-heap-overflow
description: 7-Zip versions prior to 26.06 contain a heap out-of-bounds write vulnerability in the LZX decoder that can lead to arbitrary code execution when processing crafted multi-volume CAB archives.
date: "2026-11-10T14:33:35Z"
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
qa_status:
  verdict: pass
  validation_status: Patch validation required in test environment
cpes:
  - cpe:2.3:a:7-zip:7-zip:*:*:*:*:*:*:*:*
vendors:
  - 7-Zip
products:
  - 7-Zip (< 26.06)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Attackers can entice victims to extract crafted multi-volume CAB archives, where a stale _pos value bypasses bounds checks, enabling arbitrary code execution.
    confidence_band: high
cves:
  - id: CVE-2026-125742
    cvss: 7.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-125742
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  hunt_leads:
    - lead: Identify endpoints executing 7-Zip command line utilities or GUI processes on untrusted multi-volume CAB files
      technique_id: T1203
      data_needed:
        - Process creation logs (Event ID 1) containing 7z.exe or 7zg.exe
        - File access/CLI argument logs showing .cab extensions
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Attackers can entice victims to extract crafted multi-volume CAB archives
  mitigation_plan:
    - priority: immediate
      action: Upgrade 7-Zip to version 26.06 or later
      owner: IT Operations
      addresses: CVE-2026-125742
      evidence: 7-Zip before 26.06 contains a heap out-of-bounds write vulnerability
---

7-Zip versions before 26.06 are vulnerable to a heap out-of-bounds write vulnerability within the LZX decoder. The issue arises when the software processes multi-volume CAB archives where a continuation volume declares a smaller window size than the original. This discrepancy results in a stale _pos value that bypasses internal bounds checks, potentially allowing for arbitrary code execution if a user extracts a malicious CAB archive.

## Impact

Successful exploitation allows for arbitrary code execution in the context of the user running the 7-Zip extraction process.

## Recommendation

* Update 7-Zip to version 26.06 or later across all managed endpoints to remediate CVE-2026-125742.
* Restrict the opening of untrusted multi-volume CAB files until software updates are applied.
