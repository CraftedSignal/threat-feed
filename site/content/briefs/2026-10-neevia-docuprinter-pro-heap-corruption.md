---
brief_id: brief-2026-10-28-neevia-docuprinter-pro-heap-corruption
event_id: brief-2026-10-28-neevia-docuprinter-pro-heap-corruption
revision: 1
activity_at: "2026-10-28T05:47:18Z"
title: 'Neevia docuPrinter Pro: TIFFCP.EXE heap corruption (CVE-2025-55891)'
slug: 2026-10-neevia-docuprinter-pro-heap-corruption
description: A public proof-of-concept exploit exists for CVE-2025-55891, a heap corruption vulnerability in Neevia docuPrinter Pro caused by an outdated libtiff library that triggers a crash during malformed LZW decompression.
date: "2026-10-28T05:47:18Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Vulnerability confirmed via source PoC description; patch availability pending vendor verification.
cpes:
  - cpe:2.3:a:neevia:docuprinter_pro:*:*:*:*:*:*:*:*
  - cpe:2.3:a:libtiff:libtiff:3.5.7:*:*:*:*:*:*:*
vendors:
  - Neevia
products:
  - docuPrinter Pro (<= 7.3)
  - libtiff (3.5.7)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: By supplying a specially crafted TIFF file, an attacker can trigger a segmentation fault during LZW decompression.
    confidence_band: high
cves:
  - id: CVE-2025-55891
    kev_status: unknown
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-TERRIBLEDACTYL-CVE-2025-55891
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-TERRIBLEDACTYL-CVE-2025-55891&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory docuPrinter Pro installations and verify version status
      owner: IT Operations
      due: 48h
      evidence: Vulnerability affects docuPrinter Pro 7.3 and earlier.
  hunt_leads:
    - lead: Identify crashes of TIFFCP.EXE in Windows Error Reporting (WER) or system logs
      technique_id: T1203
      data_needed:
        - Windows Application Event Logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: On Windows, the crash results in a STATUS_ACCESS_VIOLATION.
  mitigation_plan:
    - priority: immediate
      action: Disable use of TIFFCP.EXE for untrusted input processing until patched
      owner: IT Operations
      addresses: CVE-2025-55891
      evidence: Exploitation relies on malformed TIFF LZW decompression.
---

A heap corruption vulnerability (CVE-2025-55891) has been identified in `TIFFCP.EXE`, a command-line utility bundled with Neevia docuPrinter Pro 7.3 and earlier. The vulnerability stems from the use of libtiff version 3.5.7, which contains an unsafe assertion in the LZW decoding logic (`tif_lzw.c`). An attacker can trigger a segmentation fault or a `STATUS_ACCESS_VIOLATION` by supplying a specially crafted TIFF file. This issue affects both the proprietary Windows binary and open-source versions compiled from the affected libtiff code.

## Impact
Successful exploitation causes the `TIFFCP.EXE` process to crash, resulting in a denial-of-service for the application. No special privileges are required to trigger the memory access violation.

## Recommendation
- Inventory systems for installed instances of Neevia docuPrinter Pro version 7.3 and earlier.
- Apply patches provided by Neevia Technology for docuPrinter Pro as soon as they become available.
- Implement file-type validation or sandboxed processing for any TIFF images handled by docuPrinter Pro if immediate patching is not possible.
