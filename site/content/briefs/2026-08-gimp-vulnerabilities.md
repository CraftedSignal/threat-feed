---
title: Multiple Arbitrary Code Execution Vulnerabilities in GIMP
slug: 2026-08-gimp-vulnerabilities
description: GIMP contains multiple vulnerabilities that can be exploited by an attacker to execute arbitrary code on the host system, typically by enticing a user to open a specially crafted file.
date: "2026-08-21T13:14:48Z"
lastmod: "2026-08-24T18:04:01Z"
type: advisory
types:
  - advisory
severities:
  - medium
vendors:
  - GIMP
products:
  - GIMP
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: An attacker can exploit multiple vulnerabilities in GIMP to execute arbitrary program code.
    confidence_band: high
cves:
  - id: CVE-2026-78465
    cvss: 7
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2957
  - https://nvd.nist.gov/vuln/detail/CVE-2026-78465
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Update all GIMP installations
      owner: IT Operations
      due: 72h
      evidence: General security best practice for arbitrary code execution vulnerabilities.
updates:
  - at: "2026-08-24T18:04:01Z"
    level: L2
    summary: added CVE-2026-78465
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-78465
---

The GNU Image Manipulation Program (GIMP) contains multiple security vulnerabilities that allow for arbitrary code execution. These flaws are triggered when a user opens a specially crafted file, such as a malformed image, within the application. Because GIMP is widely used across various operating systems, including Windows, Linux, and macOS, this issue affects a broad user base. Successful exploitation allows an attacker to execute malicious code with the permissions of the local user who opens the file. Defenders should prioritize updating GIMP installations to the latest available version to mitigate these risks.

## Impact

The vulnerability results in arbitrary code execution, which can lead to complete system compromise, data theft, or the installation of further malware on the host machine. If an attacker successfully targets a user with elevated privileges or uses the system as a pivot point, the risk of lateral movement and data exfiltration increases significantly.

## Recommendation

- Identify all instances of the GIMP software across the enterprise environment.
- Update all GIMP installations to the latest vendor-supplied version immediately.
- Advise users to exercise caution when opening image files from untrusted or unknown sources.
