---
title: Leantime Authenticated LFI and SSRF via Blueprints
slug: 2026-07-leantime-lfi-ssrf
description: Leantime 3.6.2 contains a vulnerability in the Blueprints::import method allowing authenticated attackers to perform SSRF and LFI via the JSON-RPC API.
date: "2026-07-30T19:30:56Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - leantime
  - lfi
  - ssrf
  - cve-2026-66415
vendors:
  - Leantime
products:
  - Leantime (3.6.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An authenticated attacker can leverage the JSON-RPC API to read sensitive internal files or query cloud metadata services by injecting path traversal sequences or URL wrappers.
    confidence_band: high
cves:
  - id: CVE-2026-66415
    cvss: 8.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-66415
---

Leantime version 3.6.2 is susceptible to a combined server-side request forgery (SSRF) and local file inclusion (LFI) vulnerability stemming from improper input validation. The vulnerability exists within the Blueprints::import() method, which utilizes the user-supplied filename parameter directly within the PHP file_get_contents() function without sufficient sanitization or path validation. An authenticated attacker can exploit this flaw by submitting a crafted JSON-RPC API request containing path traversal sequences (such as ../) or URL wrappers (like file:// or http://). 

This issue allows an attacker to bypass intended access controls to read sensitive files from the underlying server filesystem, such as configuration files, or to conduct SSRF attacks to target internal services and cloud metadata endpoints. Because the vulnerability is reachable through the application's JSON-RPC API, any authenticated user - including those with low-privileged accounts - can escalate their access to extract system information or perform internal reconnaissance, potentially leading to full system compromise depending on the server configuration.

## Impact

Successful exploitation allows authenticated attackers to perform arbitrary file reads or pivot into internal network infrastructure. This vulnerability poses a significant risk to organizations hosting Leantime in cloud environments, where attackers may retrieve metadata credentials. Unauthorized access to system configuration files may lead to the exposure of database credentials, encryption keys, and other secrets, facilitating further exploitation or data exfiltration.

## Recommendation

1. Upgrade Leantime instances to the latest secure version immediately to remediate CVE-2026-66415.
2. Implement strict input validation and sanitization for all parameters passed to file-system related functions in the application code.
3. Restrict access to the JSON-RPC API to trusted users and monitor API logs for anomalous requests containing path traversal characters or URL protocols.
4. Enforce principle of least privilege for the service account running the Leantime application to limit the scope of potential file access.
