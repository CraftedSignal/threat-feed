---
title: Path Traversal Vulnerability in Whistle
slug: 2026-08-whistle-path-traversal
description: The Whistle npm package contains a path traversal vulnerability (CVE-2026-55629) in the /cgi-bin/temp/get endpoint, allowing unauthorized attackers to read arbitrary files from the filesystem.
date: "2026-08-25T18:48:58Z"
type: advisory
types:
  - advisory
severities:
  - high
products:
  - whistle (2.10.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: The code does not block the request. Instead, it directly uses the user-supplied filename for file reading.
    confidence_band: high
cves:
  - id: CVE-2026-55629
    epss: 0.00669
references:
  - https://github.com/advisories/GHSA-3vfr-4gwf-qxfp
  - https://nvd.nist.gov/vuln/detail/CVE-2026-55629
rules:
  - title: Detects CVE-2026-55629 Exploitation - Whistle Path Traversal
    description: Detects attempts to exploit CVE-2026-55629 by monitoring for requests to the /cgi-bin/temp/get endpoint with directory traversal sequences or common sensitive file paths in the filename parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1083
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade Whistle to version 2.10.3 or higher
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-55629 patch requirement
  mitigation_plan:
    - priority: immediate
      action: Deploy detection rule for /cgi-bin/temp/get exploitation
      owner: Detection Engineering
      addresses: CVE-2026-55629
      evidence: Detection rule provided
---

Whistle, an HTTP proxy tool, is susceptible to a path traversal vulnerability identified as CVE-2026-55629. The flaw resides in the service.js file, specifically within the /cgi-bin/temp/get route. The application implements a regex check (TEMP_FILE_RE) intended to restrict file access to a designated directory; however, the validation logic is flawed. If the provided filename parameter does not match the expected pattern, the application fails to reject the request. Instead, it processes the unsanitized user-supplied input directly, enabling the retrieval of arbitrary files outside of the intended directory. This vulnerability affects Whistle versions prior to 2.10.3 and poses a significant risk as it allows an unauthenticated remote attacker to read sensitive system files, such as /etc/passwd or /etc/hosts, simply by supplying a path as a query parameter.

## Attack Chain

1. Attacker performs reconnaissance to identify a server running an outdated version of Whistle (v < 2.10.3).
2. Attacker probes the /cgi-bin/temp/get endpoint to determine if path traversal is possible.
3. Attacker constructs a malicious HTTP GET request targeting the /cgi-bin/temp/get endpoint.
4. Attacker injects a path traversal sequence or an absolute path (e.g., /etc/passwd) into the 'filename' query parameter.
5. The application's service.js router receives the request and evaluates the filename against the regex.
6. Due to the flawed logic, the regex fails to catch the malicious input and passes the unsanitized filename to the getFile function.
7. The application reads the requested file from the filesystem.
8. The application returns the contents of the unauthorized file in the HTTP response body, leading to information disclosure.

## Impact

Successful exploitation of this vulnerability results in unauthorized access to sensitive files on the server hosting the Whistle proxy. This can lead to the exposure of credentials, configuration files, system identity details, and other sensitive information. The vulnerability affects any server running Whistle version 2.10.3 or lower, which is commonly used in development and debugging environments.

## Recommendation

- Upgrade the Whistle npm package to version 2.10.3 or later immediately to apply the patch for CVE-2026-55629.
- Audit existing logs for anomalous access to the /cgi-bin/temp/get endpoint, specifically looking for GET requests containing path traversal characters like "../" or absolute file paths.
- Deploy the provided Sigma rule to webserver logs to detect exploitation attempts targeting this endpoint.
- Implement network access controls to restrict access to the Whistle administration interface to trusted internal IP ranges only.
