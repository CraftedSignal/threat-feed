---
title: Summarize Path Traversal Vulnerability (CVE-2026-45242)
slug: 2026-05-summarize-path-traversal
description: Summarize versions prior to 0.15.1 are vulnerable to path traversal in the /v1/summarize daemon endpoint, allowing authenticated callers to write files to arbitrary directories via the slidesDir request parameter and subsequently delete files.
date: "2026-05-18T19:18:09Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - vulnerability
  - web-application
products:
  - Summarize < 0.15.1
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
cves:
  - id: CVE-2026-45242
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-45242
rules:
  - title: Detect Summarize Path Traversal Attempt via slidesDir
    description: Detects CVE-2026-45242 exploitation — HTTP POST requests to the /v1/summarize endpoint with path traversal sequences or absolute paths in the slidesDir parameter
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Summarize File Write via slidesDir Path Traversal
    description: Detects CVE-2026-45242 exploitation — File creation events in unexpected directories due to path traversal via the slidesDir parameter.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
rules_count: 2
---

Summarize versions prior to 0.15.1 are susceptible to a path traversal vulnerability in the `/v1/summarize` daemon endpoint. This flaw allows authenticated users to write arbitrary files to any directory on the system where the Summarize application has write permissions. The vulnerability is triggered by manipulating the `slidesDir` request parameter, enabling attackers to inject absolute paths or directory traversal sequences. This can be exploited to write `slide_*.png` and `slides.json` files to locations outside of the intended directory and subsequently delete them, potentially leading to denial of service or other unexpected behavior. Defenders should ensure that Summarize is updated to version 0.15.1 or later to mitigate this risk.

## Attack Chain

1.  Attacker authenticates to the Summarize application.
2.  Attacker crafts a malicious HTTP POST request to the `/v1/summarize` endpoint.
3.  The request includes a `slidesDir` parameter containing a path traversal sequence (e.g., `../../`) or an absolute path pointing to a sensitive directory.
4.  The Summarize application processes the request without proper sanitization of the `slidesDir` parameter.
5.  The application writes `slide_*.png` and `slides.json` files to the attacker-specified location.
6.  The attacker sends a subsequent request to trigger the file deletion functionality, targeting the previously written files.
7.  The Summarize application deletes the files at the specified location, leading to potential data loss or system instability.

## Impact

Successful exploitation allows authenticated attackers to write and delete files in arbitrary directories accessible to the Summarize application. This can lead to data corruption, denial of service, or potentially arbitrary code execution if combined with other vulnerabilities or misconfigurations. The NVD rates this vulnerability with a CVSS v3.1 base score of 7.1, indicating a high severity.

## Recommendation

*   Upgrade Summarize to version 0.15.1 or later to remediate CVE-2026-45242.
*   Deploy the Sigma rule "Detect Summarize Path Traversal Attempt via slidesDir" to identify potential exploitation attempts by monitoring HTTP requests to the `/v1/summarize` endpoint.
*   Implement input validation and sanitization on the `slidesDir` parameter to prevent path traversal attacks.
