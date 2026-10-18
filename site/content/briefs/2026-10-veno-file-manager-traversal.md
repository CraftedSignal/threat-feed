---
title: Path Traversal Vulnerability in Veno File Manager
slug: 2026-10-veno-file-manager-traversal
description: CVE-2026-37066 is a path traversal vulnerability in Veno File Manager 4.4.9 that allows an authenticated super administrator to perform arbitrary file reads via specific administrative endpoints.
date: "2026-10-18T00:12:05Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:veno_file_manager_project:veno_file_manager:*:*:*:*:*:*:*:*
vendors:
  - Veno File Manager Project
products:
  - Veno File Manager (4.4.9)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Path traversal leading to Arbitrary File Read in /vfm-admin/index.php and /vfm-admin/ajax/streamvid.php
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1005
    technique_name: Data from Local System
    evidence: Allows super admin to read arbitrary files.
    confidence_band: high
cves:
  - id: CVE-2026-37066
    cvss: 6.5
    epss: 0.00543
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-JFS-JFS-CVE-2026-37066
rules:
  - title: Detect CVE-2026-37066 Exploitation - Path Traversal in Veno File Manager
    description: Detects potential exploitation of CVE-2026-37066 by identifying directory traversal sequences in requests to administrative endpoints.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
      - initial_access
    techniques:
      - T1005
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Review logs for access patterns matching the Veno File Manager administrative endpoints.
      owner: SOC
      due: 24h
      evidence: Source document identifies /vfm-admin/index.php and /vfm-admin/ajax/streamvid.php as vulnerable.
  hunt_leads:
    - lead: Search web logs for traversal sequences targeting vfm-admin paths.
      technique_id: T1005
      data_needed:
        - Web server access logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Public exploit code suggests specific path traversal patterns.
  mitigation_plan:
    - priority: immediate
      action: Patch Veno File Manager to a non-vulnerable version if available.
      owner: IT Operations
      addresses: CVE-2026-37066
      evidence: Vulnerability affects version 4.4.9.
---

Veno File Manager version 4.4.9 contains a path traversal vulnerability identified as CVE-2026-37066. This flaw allows an authenticated attacker possessing the super administrator role to access and read arbitrary files on the server's filesystem. The vulnerability is triggered by sending specially crafted HTTP GET or POST requests to the administrative interface, specifically targeting the /vfm-admin/index.php and /vfm-admin/ajax/streamvid.php files. This vulnerability poses a significant risk for sensitive information disclosure, as it allows unauthorized access to configuration files, system data, or stored credentials residing outside the intended application directory.

## Attack Chain

1. Attacker gains authentication to the Veno File Manager administrative console with the super administrator role.
2. Attacker crafts a malicious HTTP GET or POST request targeting /vfm-admin/index.php or /vfm-admin/ajax/streamvid.php.
3. The request includes directory traversal sequences (such as ../) within the request parameters handled by the application.
4. The application fails to properly sanitize the input parameters before processing file read operations.
5. The application backend processes the request and resolves the traversal path to an arbitrary location on the underlying server filesystem.
6. The application retrieves the content of the target file.
7. The application returns the file contents to the attacker within the HTTP response body, resulting in unauthorized information disclosure.

## Impact

Successful exploitation of this vulnerability leads to unauthorized access to arbitrary files on the host server. This can result in the exposure of sensitive configuration details, database credentials, environment variables, or private data, potentially leading to complete system compromise or lateral movement if credentials or session tokens are exfiltrated.

## Recommendation

Detection engineering teams should monitor administrative traffic for anomalous directory traversal patterns.
- Deploy web server logs to monitor for requests to /vfm-admin/index.php and /vfm-admin/ajax/streamvid.php containing directory traversal strings like ../ or ..%2f.
- Ensure administrative access to Veno File Manager is restricted to trusted source IP addresses to prevent unauthorized authentication.
- Review all logs for unauthorized access by super administrator accounts if an intrusion is suspected.
