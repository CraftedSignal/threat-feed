---
title: Xerte Online Toolkits Unauthenticated Remote Code Execution via elFinder Connector
slug: 2024-01-xerte-rce
description: Xerte Online Toolkits versions 3.15 and earlier are vulnerable to unauthenticated remote code execution due to a missing authentication check in the elFinder connector, allowing arbitrary file operations that can be chained with other vulnerabilities.
date: "2024-01-24T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - CVE-2026-34413
  - xerte
  - rce
vendors:
  - Xerte
products:
  - Xerte Online Toolkits (3.15 and earlier)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-34413
    cvss: 8.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34413
rules:
  - title: Detect Unauthenticated elFinder Connector Access
    description: Detects unauthorized access attempts to the elFinder connector in Xerte Online Toolkits, indicating potential exploitation of CVE-2026-34413.
    platform: sigma
    severity: critical
    tactics:
      - cve-2026-34413
      - execution
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious File Uploads to elFinder Connector
    description: Detects potentially malicious file uploads via the elFinder connector in Xerte Online Toolkits by monitoring for specific HTTP parameters.
    platform: sigma
    severity: high
    tactics:
      - cve-2026-34413
      - execution
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Xerte Online Toolkits, a web-based open-source e-learning content creation platform, is vulnerable to a critical remote code execution vulnerability (CVE-2026-34413) affecting versions 3.15 and earlier. The vulnerability lies within the elFinder connector endpoint at `/editor/elfinder/php/connector.php`, which lacks proper authentication. This allows unauthenticated attackers to bypass intended access controls and directly interact with the file management system. Attackers can leverage this flaw to perform unauthorized file operations, including creating, uploading, renaming, duplicating, overwriting, and deleting files within project media directories. This can be chained with path traversal and extension blocklist bypass vulnerabilities to ultimately achieve remote code execution and arbitrary file read on the affected server.

## Attack Chain

1. An unauthenticated attacker sends a malicious HTTP request to `/editor/elfinder/php/connector.php` targeting the elFinder file manager.
2. Due to the missing authentication check, the server processes the request without validating the user's identity.
3. The attacker leverages the file operation functionalities (create, upload, rename, duplicate, overwrite, delete) of elFinder.
4. The attacker exploits a path traversal vulnerability to navigate outside the intended media directory.
5. The attacker uploads a malicious PHP file with a bypassed extension filter (e.g., using double extensions or null byte injection).
6. The attacker renames the uploaded file to a valid PHP extension (e.g., `.php`).
7. The attacker sends an HTTP request to the renamed PHP file, triggering server-side execution.
8. The attacker achieves remote code execution on the server, allowing for arbitrary system commands and data access.

## Impact

Successful exploitation of this vulnerability grants unauthenticated attackers the ability to execute arbitrary code on the Xerte Online Toolkits server. This can lead to complete system compromise, data theft, defacement of the learning platform, and denial of service. The severity is high due to the ease of exploitation and the potential for widespread impact across educational institutions and organizations utilizing Xerte Online Toolkits for e-learning content delivery.

## Recommendation

*   Apply the latest security patches or upgrade to a version of Xerte Online Toolkits greater than 3.15 to address CVE-2026-34413.
*   Implement the Sigma rule `Detect Unauthenticated elFinder Connector Access` to identify unauthorized access attempts to the vulnerable endpoint.
*   Review and harden file upload policies to prevent the upload of potentially malicious file types, mitigating the risk of chained exploitation.
