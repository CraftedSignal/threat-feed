---
title: Uncontrolled Search Path Vulnerability in ImageMagick on Windows
slug: 2026-10-imagemagick-search-path
description: ImageMagick versions through 7.1.2-33 and 6.9.13-58 are vulnerable to arbitrary code execution via binary planting due to an insecure search path for gswin64c.exe.
date: "2026-10-11T03:58:06Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:imagemagick:imagemagick:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - code-execution
  - windows
vendors:
  - ImageMagick
products:
  - ImageMagick (<= 7.1.2-33, <= 6.9.13-58)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1574
    technique_name: Hijack Execution Flow
    evidence: ImageMagick on Windows through 7.1.2-33 and 6.9.13-58 contains an uncontrolled search path vulnerability in NTGhostscriptEXE() that launches gswin64c.exe by bare name.
    confidence_band: high
cves:
  - id: CVE-2026-108693
    cvss: 7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-108693
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  mitigation_plan:
    - priority: immediate
      action: Register Ghostscript in the Windows system environment variables or update ImageMagick to a patched version once released.
      owner: IT Operations
      addresses: CVE-2026-108693
      evidence: Source documentation identifies insecure search path in NTGhostscriptEXE() when Ghostscript is unregistered.
---

ImageMagick on Windows, specifically versions through 7.1.2-33 and 6.9.13-58, contains an uncontrolled search path vulnerability within the NTGhostscriptEXE() function. When the Ghostscript utility is not explicitly registered in the system environment, ImageMagick attempts to locate and execute the 'gswin64c.exe' binary using its bare name. This behavior allows the application to search the current working directory before system-wide paths. An attacker with the ability to influence the working directory of the ImageMagick process - often by inducing a user to convert a malicious PDF, PostScript, or EPS file - can plant a rogue executable named 'gswin64c.exe'. When ImageMagick is triggered to process the file, it will execute the attacker-supplied binary with the privileges of the ImageMagick process, leading to arbitrary code execution.

## Impact

Successful exploitation allows local arbitrary code execution with the permissions of the user running the ImageMagick utility. This vulnerability impacts all Windows deployments of ImageMagick within the specified version ranges that have not registered Ghostscript globally. If exploited, an attacker could achieve persistence, exfiltrate local data, or pivot within the host environment.

## Recommendation

Prioritize patching ImageMagick to a version beyond 7.1.2-33 or 6.9.13-58 as soon as an official fix is provided by the vendor. In the interim, ensure Ghostscript is correctly registered in the system environment variables to prevent the application from defaulting to insecure local path lookups for 'gswin64c.exe'.
