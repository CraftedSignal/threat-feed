---
title: SiYuan Path Traversal Vulnerability (CVE-2026-40318)
slug: 2024-01-19-siyuan-path-traversal
description: SiYuan versions 3.6.3 and prior are vulnerable to path traversal (CVE-2026-40318), allowing attackers to delete arbitrary .json files on the server via the /api/av/removeUnusedAttributeView endpoint.
date: "2024-01-19T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - path-traversal
  - vulnerability
  - siyuan
vendors:
  - SiYuan
products:
  - SiYuan
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1565
    technique_name: Data Manipulation
cves:
  - id: CVE-2026-40318
    cvss: 8.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40318
rules:
  - title: SiYuan Path Traversal - Attempted File Deletion
    description: Detects attempts to exploit CVE-2026-40318 by identifying path traversal sequences in requests to the /api/av/removeUnusedAttributeView endpoint.
    platform: sigma
    severity: critical
    tactics:
      - impact
    techniques:
      - T1565
    data_sources:
      - webserver
      - linux
  - title: SiYuan Path Traversal - Double Encoding Attempt
    description: Detects attempts to bypass path traversal filters using double encoding in requests to the /api/av/removeUnusedAttributeView endpoint.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1565
    data_sources:
      - webserver
      - linux
  - title: SiYuan Path Traversal - Non-Standard Encoding Attempt
    description: Detects attempts to bypass path traversal filters using non-standard encoding in requests to the /api/av/removeUnusedAttributeView endpoint.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1565
    data_sources:
      - webserver
      - linux
rules_count: 3
---

SiYuan, an open-source personal knowledge management system, is affected by a critical path traversal vulnerability identified as CVE-2026-40318. This flaw resides within the /api/av/removeUnusedAttributeView endpoint in versions 3.6.3 and earlier. The application constructs a filesystem path using the user-supplied 'id' parameter without proper validation. This lack of validation allows an attacker to inject path traversal sequences like "../" into the 'id' value, enabling them to navigate outside the intended directory. Successful exploitation permits the deletion of arbitrary .json files on the server, including critical global configuration files and workspace metadata. The vulnerability has been patched in version 3.6.4. This poses a significant threat to the integrity and availability of SiYuan installations.

## Attack Chain

1. An attacker identifies a vulnerable SiYuan instance running version 3.6.3 or earlier.
2. The attacker crafts a malicious HTTP POST request targeting the `/api/av/removeUnusedAttributeView` endpoint.
3. Within the POST request, the attacker includes the `id` parameter with a path traversal sequence, such as `"../"`, followed by the path to a sensitive .json file (e.g., `"../../config/config.json"`).
4. The SiYuan server receives the request and, due to the lack of input validation, constructs a file path incorporating the malicious path traversal sequence.
5. The server attempts to delete the file specified by the constructed path, which, due to the path traversal, resides outside the intended directory.
6. The targeted .json file is successfully deleted from the server.
7. The attacker repeats this process to delete other critical .json files, such as workspace metadata, potentially disrupting the SiYuan instance's functionality and data integrity.
8. The attacker achieves the objective of arbitrary file deletion leading to service disruption or data loss.

## Impact

Successful exploitation of CVE-2026-40318 allows an attacker to delete arbitrary .json files on the SiYuan server. This includes global configuration files, potentially leading to a complete loss of configuration, and workspace metadata, which can render user workspaces inaccessible. The impact of this vulnerability is high, as it can lead to significant data loss, service disruption, and potential compromise of sensitive information stored within the SiYuan application. The deletion of configuration files can also enable an attacker to potentially reconfigure the application to their benefit.

## Recommendation

*   Upgrade SiYuan to version 3.6.4 or later to patch CVE-2026-40318.
*   Deploy the Sigma rule `SiYuan_Path_Traversal_Delete` to detect attempts to exploit CVE-2026-40318 in web server logs.
*   Monitor web server logs for suspicious requests containing path traversal sequences (e.g., "../") in the `cs-uri-query` targeting the `/api/av/removeUnusedAttributeView` endpoint.
