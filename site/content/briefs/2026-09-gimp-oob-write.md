---
title: Out-of-Bounds Write Vulnerability in GIMP Lighting Effects Filter (CVE-2026-90947)
slug: 2026-09-gimp-oob-write
description: GIMP contains an out-of-bounds write vulnerability in its Lighting Effects filter, allowing potential arbitrary code execution when processing a maliciously crafted lighting preset file.
date: "2026-09-14T17:34:53Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
vendors:
  - GIMP
products:
  - GIMP (all versions prior to fix)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: An attacker could exploit this by convincing a user to open a malicious preset file, potentially causing a crash or enabling arbitrary code execution.
    confidence_band: high
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90947
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade GIMP across the enterprise
      owner: IT Operations
      due: 72h
      evidence: Source document identifies CVE-2026-90947 in GIMP
  mitigation_plan:
    - priority: immediate
      action: Update GIMP to the latest version
      owner: IT Operations
      addresses: CVE-2026-90947
      evidence: NVD vulnerability entry
---

A memory corruption vulnerability (CVE-2026-90947) has been identified in the GIMP image manipulation software. The flaw resides within the Lighting Effects filter, which fails to correctly validate the number of light sources defined within a GIMP lighting preset file. When a user opens a specially crafted preset file containing an unexpected number of light sources, the application performs an out-of-bounds write operation, leading to memory corruption. This vulnerability exposes users to potential application crashes or, in specific scenarios, arbitrary code execution in the context of the user running the application. This issue impacts GIMP across all supported platforms, including Windows, Linux, and macOS. Defenders should prioritize patching GIMP versions to the latest available release as identified by the project's security advisories.

## Impact

Successful exploitation of CVE-2026-90947 could lead to full compromise of the user account running GIMP. This threat is particularly relevant in environments where users frequently import or share graphical design presets. If the application is running with elevated privileges, the impact of arbitrary code execution is significantly magnified. There is currently no report of large-scale exploitation in the wild, but the nature of the flaw makes it a viable candidate for targeted social engineering attacks.

## Recommendation

1. Upgrade all instances of GIMP to the latest version provided by the GIMP development team that addresses CVE-2026-90947.
2. Implement application allowlisting or restricted execution policies for image processing software to limit the impact of potential arbitrary code execution.
3. Educate users regarding the risks of opening external preset files or image configuration files from untrusted sources.
