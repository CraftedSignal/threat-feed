---
title: Heap Over-read Vulnerability in DCMTK ConcatenationLoader
slug: 2026-09-dcmtk-heap-over-read
description: DCMTK version 3.7.0 and earlier contains a heap over-read vulnerability in the ConcatenationLoader component that can lead to information disclosure or application crashes when processing malformed DICOM files.
date: "2026-09-24T14:47:40Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:offis:dcmtk:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - dcmtk
  - dicom
  - medical-imaging
vendors:
  - OFFIS
products:
  - DCMTK (<= 3.7.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An attacker can craft malicious DICOM instances declaring more frames than the buffer contains to trigger heap over-reads that crash the application or leak adjacent heap memory.
    confidence_band: high
cves:
  - id: CVE-2026-97059
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-97059
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Inventory all applications leveraging the DCMTK library and verify current versioning.
      owner: Application Security
      due: 72h
      evidence: DCMTK (<= 3.7.0) is the affected version range identified in the source.
  mitigation_plan:
    - priority: medium_term
      action: Upgrade DCMTK to a patched version once released by the vendor.
      owner: IT Operations
      addresses: CVE-2026-97059
      evidence: Source identifies CVE-2026-97059 as a heap over-read in version 3.7.0.
---

DCMTK (DICOM Toolkit) through version 3.7.0 is susceptible to a heap over-read vulnerability within the ConcatenationLoader component. The issue stems from insufficient validation of pixel data frames; specifically, the component fails to verify that the length of the PixelData buffer matches the quantity declared in the NumberOfFrames attribute. 

An attacker can exploit this by crafting a malicious DICOM file containing a deliberately mismatched NumberOfFrames field. When an application utilizing this library parses the malformed file, it triggers an out-of-bounds read on the heap. This behavior may result in a crash of the service processing the DICOM data or, in specific memory layouts, the disclosure of sensitive data residing in adjacent memory segments. Given that DCMTK is widely used in medical imaging software and PACS (Picture Archiving and Communication Systems) infrastructures, this vulnerability poses a significant risk to the confidentiality and availability of sensitive patient imaging data.

## Impact

Successful exploitation allows for memory content disclosure or denial-of-service via application crash. The impact is significant for organizations operating medical imaging environments, as any downstream application integrating the vulnerable DCMTK library is susceptible to attacks via maliciously crafted DICOM files.

## Recommendation

Prioritized actions focus on identifying and upgrading vulnerable library dependencies within the software supply chain:

- Audit all internal and third-party software deployments to identify applications that statically or dynamically link against DCMTK version 3.7.0 or earlier.
- Prioritize patching for internet-facing or externally accessible image processing services that ingest DICOM files from untrusted sources.
- Monitor vendor security advisories from OFFIS regarding the release of a patched version of DCMTK that implements proper buffer length validation for the ConcatenationLoader.
