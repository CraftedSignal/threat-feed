---
title: Heap-Based Buffer Overflow in Autodesk AutoCAD
slug: 2026-07-autodesk-dxf-overflow
description: A heap-based buffer overflow vulnerability in Autodesk AutoCAD, AutoCAD LT, and DWG TrueView allows attackers to execute arbitrary code via maliciously crafted DXF files.
date: "2026-07-29T16:18:23Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Autodesk
products:
  - AutoCAD
  - AutoCAD LT
  - DWG TrueView
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: A maliciously crafted DXF file, when parsed through Autodesk AutoCAD, can force a Heap-Based Overflow vulnerability.
    confidence_band: high
cves:
  - id: CVE-2026-16463
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-16463
  - https://www.autodesk.com/trust/security-advisories/adsk-sa-2026-0009
---

Autodesk has disclosed a critical heap-based buffer overflow vulnerability, tracked as CVE-2026-16463, affecting AutoCAD, AutoCAD LT, and DWG TrueView. The vulnerability resides in the software's parsing logic for Drawing Interchange Format (DXF) files. An attacker can exploit this flaw by providing a specially crafted DXF file to a victim. Upon opening or parsing the malicious file, the application triggers a heap-based buffer overflow, which can lead to application crashes, unauthorized disclosure of sensitive data, or remote code execution within the security context of the user process. The vulnerability requires user interaction to execute, typically involving the victim opening the file. Impacted versions include all releases prior to the 2027.1.0 update. Defenders should prioritize patching, as this vulnerability allows for full code execution via standard file-parsing vectors.

## Impact

Successful exploitation of CVE-2026-16463 allows an unauthenticated attacker to achieve arbitrary code execution on a target system. This could lead to full system compromise, exfiltration of sensitive design files, or the installation of persistent malware. Organizations in engineering, architecture, and manufacturing sectors that rely heavily on AutoCAD are at the highest risk.

## Recommendation

* Apply the 2027.1.0 update or later to all instances of Autodesk AutoCAD, AutoCAD LT, and DWG TrueView to remediate CVE-2026-16463.
* Implement file type filtering at the mail gateway and web proxy to restrict the intake of unexpected or untrusted .dxf files from external sources.
* Monitor endpoint telemetry for suspicious child processes spawned by acad.exe or related Autodesk binaries.
* Utilize application control policies to restrict the execution of untrusted software or the opening of CAD files from high-risk locations.
