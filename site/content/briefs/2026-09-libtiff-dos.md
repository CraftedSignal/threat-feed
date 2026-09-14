---
title: Denial of Service Vulnerability in libTIFF
slug: 2026-09-libtiff-dos
description: A memory corruption vulnerability in libTIFF allows a local attacker to cause a crash or Denial of Service condition through a specially crafted TIFF file.
date: "2026-09-14T19:02:56Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:libtiff:libtiff:*:*:*:*:*:*:*:*
  - cpe:2.3:a:libtiff:libtiff:4.5.0:-:*:*:*:*:*:*
vendors:
  - LibTIFF
products:
  - libtiff (all versions containing CVE-2023-26966)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Ein lokaler Angreifer kann eine Schwachstelle in libTIFF ausnutzen, um einen Denial-of-Service-Zustand oder eine Speicherbeschädigung zu verursachen.
    confidence_band: high
cves:
  - id: CVE-2023-26966
    cvss: 5.5
    epss: 0.00417
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3338
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Vulnerability Management
  mitigation_plan:
    - priority: medium_term
      action: Patch and update all software applications and system binaries utilizing vulnerable versions of libTIFF to remediate CVE-2023-26966.
      owner: IT Operations
      addresses: CVE-2023-26966
      evidence: Source documentation identifies this vulnerability as requiring remediation via updates.
---

The BSI has reported a vulnerability in libTIFF (tracked as CVE-2023-26966) that permits a local attacker to induce a Denial of Service (DoS) state or achieve memory corruption. This issue arises from improper handling of image data structures within the library, which is widely utilized for TIFF file processing across various desktop and server-side applications. Because libTIFF acts as a foundational dependency for numerous graphics editors, PDF renderers, and web server modules, the exploitability of this flaw depends on the specific application implementation and the privileges of the user interacting with the malicious file. Defenders should prioritize auditing software dependencies for versions of libTIFF containing this vulnerability, particularly in environments where untrusted TIFF files are processed by privileged services or administrative tools.

## Impact

The vulnerability potentially allows an attacker to crash critical services or applications, leading to a Denial of Service condition. In more severe scenarios, the underlying memory corruption could theoretically be leveraged for unauthorized code execution, though the report specifically highlights crash-inducing behavior. Systems, services, or users that frequently process arbitrary or externally supplied TIFF images are at the highest risk of exploitation.

## Recommendation

Prioritize the identification of applications or services within the enterprise that dynamically link against vulnerable versions of libTIFF. 
- Update all software packages and libraries that utilize libTIFF to the latest patched version provided by the upstream maintainers or OS package managers.
- Review patch management reports for CVE-2023-26966 to identify affected third-party binaries that require manual updates or configuration hardening.
