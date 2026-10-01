---
title: Zip Slip Vulnerability in Prime Mover WordPress Plugin
slug: 2026-10-prime-mover-zip-slip
description: The Prime Mover WordPress plugin before version 2.2.1 is vulnerable to Zip Slip, allowing authenticated administrators to perform arbitrary file writes via path traversal during ZIP archive extraction.
date: "2026-10-01T18:13:01Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:wp-prime-mover:prime-mover:*:*:*:*:*:wordpress:*:*
vendors:
  - WordPress
products:
  - Prime Mover (< 2.2.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Prime Mover plugin for WordPress before 2.2.1 contains a Zip Slip path traversal vulnerability that allows authenticated administrators to write arbitrary files outside the intended extraction directory during migration ZIP import.
    confidence_band: high
cves:
  - id: CVE-2026-101888
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-101888
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Update Prime Mover plugin to version 2.2.1 or later.
      owner: IT Operations
      addresses: CVE-2026-101888
      evidence: Source documentation for CVE-2026-101888
---

The Prime Mover plugin for WordPress, prior to version 2.2.1, contains a Zip Slip vulnerability residing in its migration ZIP import functionality. This vulnerability occurs because the plugin fails to properly sanitize the filenames of entries within uploaded ZIP archives during the extraction process. Specifically, the functions computeExtractionParameters() and resumableZipExtractor(), located within utilities/PrimeMoverSystemCheckUtilities.php, process entry names containing path traversal sequences. An authenticated administrator can craft a malicious ZIP archive containing entries with relative path components (e.g., ../) to force the application to extract files outside of the intended directory. This permits an attacker to overwrite critical system or application files, potentially leading to remote code execution if the environment is configured to interpret or execute the attacker-controlled files.

## Impact

The vulnerability allows for arbitrary file write and potential remote code execution on the affected WordPress site. Successful exploitation requires an authenticated administrative account, limiting the initial vector to users with existing high-privilege access. If exploited, an attacker could gain full control over the web application environment by overwriting configuration files or injecting web shells into reachable directories.

## Recommendation

Update the Prime Mover plugin to version 2.2.1 or later to remediate the Zip Slip path traversal vulnerability (CVE-2026-101888).

## Reference

- https://nvd.nist.gov/vuln/detail/CVE-2026-101888
