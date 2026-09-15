---
title: Heap-Based Buffer Overflow in Ghostscript JPEG 2000 Output Adapter
slug: 2026-09-ghostscript-buffer-overflow
description: Ghostscript versions prior to 10.08.0 are vulnerable to a heap-based buffer overflow in the JPEG 2000 output adapter (CVE-2026-39919), potentially allowing arbitrary code execution via a specially crafted PDF.
date: "2026-09-15T15:40:57Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:artifex:ghostscript:*:*:*:*:*:*:*:*
vendors:
  - Artifex Software
products:
  - Ghostscript (< 10.08.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: This causes an overflow that corrupts internal chunk-allocator metadata, potentially leading to arbitrary code execution when the file is processed.
    confidence_band: high
cves:
  - id: CVE-2026-39919
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-39919
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  mitigation_plan:
    - priority: immediate
      action: Upgrade Ghostscript to 10.08.0 or later
      owner: IT Operations
      addresses: CVE-2026-39919
      evidence: Source identified the vulnerability in versions prior to 10.08.0
---

Ghostscript before version 10.08.0 contains a critical heap-based buffer overflow vulnerability within its JPEG 2000 output adapter, specifically located in the `base/sjpx_openjpeg.c` file. This vulnerability is triggered when the software processes a maliciously crafted PDF document that includes a JPEG 2000 image with mismatched component subsampling factors. 

When these image components declare conflicting subsampling values, the application triggers a faulty path in the non-samescale sub-byte-depth output logic. The system allocates a row buffer sized for packed output but proceeds to write a full byte per output column, regardless of the actual bit depth. This discrepancy leads to an out-of-bounds write that corrupts internal chunk-allocator metadata. Attackers can leverage this corruption to overwrite control structures or pointers, potentially achieving arbitrary code execution within the context of the user or service account running the Ghostscript binary.

## Impact

Successful exploitation allows for arbitrary code execution on systems using Ghostscript for image or document processing. Given Ghostscript's common role as a backend component for web servers, document management systems, and print servers, the attack surface is significant. Exploitation can lead to full system compromise or unauthorized access to sensitive internal data processed by these applications.

## Recommendation

Prioritized, concrete actions for detection engineering and security teams:

- Upgrade all installations of Ghostscript to version 10.08.0 or later immediately to patch CVE-2026-39919.
- Audit infrastructure to identify applications utilizing Ghostscript for PDF or image conversion, focusing on internet-facing web applications or document upload services.
- Implement restrictive sandboxing or containerization for processes invoking the Ghostscript binary to limit the impact of potential exploitation.
