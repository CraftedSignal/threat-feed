---
brief_id: brief-2026-11-03-hdf5-heap-buffer-over-read
event_id: brief-2026-11-03-hdf5-heap-buffer-over-read
revision: 1
activity_at: "2026-11-03T22:18:35Z"
title: 'HDF5: Heap buffer over-read in H5L__extern_traverse (CVE-2026-120757)'
slug: 2026-11-hdf5-heap-buffer-over-read
description: HDF5 versions 2.2.0 and earlier contain a heap buffer over-read vulnerability in the external link traversal callback that can be triggered by a crafted file, potentially leading to denial of service or information disclosure.
date: "2026-11-03T22:18:35Z"
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
  validation_status: Verified against CVE-2026-120757 entry.
cpes:
  - cpe:2.3:a:hdfgroup:hdf5:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - hdf5
  - heap-overflow
  - memory-safety
vendors:
  - The HDF Group
products:
  - HDF5 (<= 2.2.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: The flaw is triggered when the malicious link is traversed, for example when opening an object through it.
    confidence_band: high
cves:
  - id: CVE-2026-120757
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120757
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Inventory all applications and services within the environment that dynamically link to or embed HDF5 libraries.
      owner: IT Operations
      due: 48h
      evidence: Affected products identified as HDF5 <= 2.2.0.
  hunt_leads:
    - lead: Monitor application crash logs (e.g., core dumps, Windows Error Reporting) associated with applications that process HDF5 files to identify patterns of heap corruption.
      technique_id: T1203
      data_needed:
        - Application error logs
        - System crash reporting telemetry
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The overrun is unbounded and continues until a zero byte is found, likely resulting in memory access violations.
  mitigation_plan:
    - priority: immediate
      action: Upgrade HDF5 to a version released after 2.2.0 that includes patches for the H5L__extern_traverse buffer validation.
      owner: IT Operations
      addresses: CVE-2026-120757
      evidence: NVD vulnerability entry identifies version 2.2.0 and earlier as affected.
---

HDF5 through version 2.2.0 contains a heap buffer over-read vulnerability in the `H5L__extern_traverse()` function within `src/H5Lexternal.c`. The flaw stems from the use of `strlen()` to process link user data without validating the buffer size or checking for NULL termination. An attacker can supply a specially crafted HDF5 file containing an external link that, when traversed, triggers an unbounded read of memory beyond the heap buffer. This behavior can lead to application crashes (denial of service) or allow sensitive data in adjacent heap memory to be leaked into the file path or object path buffers.

## Impact

An attacker can induce a denial of service by crashing the application. Additionally, there is a risk of information disclosure where adjacent heap contents are incorporated into the external file name or object path, which the library subsequently attempts to open.

## Recommendation

- Audit applications utilizing HDF5 libraries to identify versions 2.2.0 or older.
- Prioritize upgrading to a patched release of HDF5 as soon as it becomes available from The HDF Group.
- Implement file integrity and validation checks for HDF5 files ingested from untrusted or external sources to prevent the processing of malicious link structures.
