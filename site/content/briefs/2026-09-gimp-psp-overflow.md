---
title: Heap-Based Buffer Overflow in GIMP PSP File Loader
slug: 2026-09-gimp-psp-overflow
description: A heap-based buffer overflow in GIMP's PSP file loader, tracked as CVE-2026-90949, allows attackers to trigger crashes or arbitrary code execution via crafted image files.
date: "2026-09-14T15:33:53Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:gimp:gimp:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - memory-corruption
vendors:
  - GIMP
products:
  - GIMP (affected versions)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: Opening this file in GIMP could lead to a crash or arbitrary code execution.
    confidence_band: high
cves:
  - id: CVE-2026-90949
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90949
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Monitor for and apply GIMP patches as released to address CVE-2026-90949
      owner: IT Operations
      addresses: CVE-2026-90949
      evidence: A flaw was found in GIMP's PSP (Paint Shop Pro) file loader.
---

CVE-2026-90949 is a vulnerability identified in the Paint Shop Pro (PSP) file loader component of the GIMP image manipulation software. The issue arises during the processing of compressed selection channels within PSP files. A mismatch between the allocated buffer size and the actual amount of data decompressed by the loader results in a heap-based buffer overflow. An attacker can leverage this flaw by distributing a specially crafted PSP file to a victim. When the victim opens the malicious file using an affected version of GIMP, the resulting memory corruption may cause the application to crash or enable the execution of arbitrary code in the context of the user running the application. This vulnerability poses a significant risk to end-users who may interact with untrusted image files.

## Impact

Successful exploitation of CVE-2026-90949 can lead to a denial-of-service (application crash) or full code execution on the host machine. This affects any user or organization utilizing GIMP for processing image assets. The impact is elevated if the application is run with higher-privilege user context.

## Recommendation

- Identify all systems where GIMP is installed and monitor vendor release notes for the patched version addressing CVE-2026-90949.
- Implement strict email and web gateway filtering to block PSP (Paint Shop Pro) file formats from untrusted external sources if your environment does not require this file format.
- Advise end-users to avoid opening PSP files from unknown or unverified sources until the software is patched.
