---
title: Banana Slides Path Traversal Vulnerability (CVE-2026-49136)
slug: 2026-06-banana-slides-path-traversal
description: Banana Slides version 0.4.0 contains a path traversal vulnerability (CVE-2026-49136) in the generate_image() function that allows unauthenticated attackers to read arbitrary image-format files outside the intended uploads directory by exploiting an incomplete path prefix check.
date: "2026-06-01T21:19:30Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - web-application
  - cve
products:
  - Banana Slides <= 0.4.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-49136
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-49136
  - CVE-2026-49136
rules:
  - title: Detect CVE-2026-49136 Exploitation Attempt - Path Traversal in Banana Slides
    description: Detects CVE-2026-49136 exploitation attempt - Path traversal vulnerability in Banana Slides via crafted HTTP request.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-49136 Exploitation Attempt - os.path.startswith bypass
    description: Detects CVE-2026-49136 exploitation attempt by looking for requests targeting directories with the 'uploads' prefix but outside the uploads directory.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

Banana Slides version 0.4.0 is vulnerable to a path traversal vulnerability, identified as CVE-2026-49136, within the AI service backend's `generate_image()` function. This flaw allows unauthenticated attackers to bypass intended directory confinement, reading arbitrary image-format files from outside the uploads directory. The vulnerability stems from an incomplete path prefix check using `os.path.startswith()` without a trailing separator. By crafting markdown image references in user-controlled page descriptions, attackers can target sibling directories sharing the uploads folder prefix. This bypasses the intended security measure, enabling unauthorized file access via PIL `Image.open()`. The vulnerability was patched in commit e8bc490.

## Attack Chain

1. An unauthenticated attacker crafts a malicious payload containing a markdown image reference within a user-controlled page description. This payload is designed to exploit the path traversal vulnerability.
2. The crafted markdown image reference includes a path that resolves to a sibling directory whose name shares the same prefix as the uploads directory (e.g., if the uploads directory is `/var/www/bananaslides/uploads`, a sibling directory might be `/var/www/bananaslides/uploads_backup`).
3. The `generate_image()` function in the AI service backend processes the markdown content and attempts to generate the image.
4. The application uses `os.path.startswith()` to validate that the path of the requested image begins with the uploads directory path. However, the check lacks a trailing separator (e.g., `/var/www/bananaslides/uploads/`).
5. Due to the missing trailing separator, the check incorrectly validates paths to sibling directories that share the prefix.
6. The application then uses PIL's `Image.open()` function to open and process the image file located at the attacker-controlled path.
7. Because the path traversal was successful, the application reads the contents of an arbitrary image file outside the intended uploads directory.
8. The attacker successfully retrieves the contents of the targeted file.

## Impact

Successful exploitation of CVE-2026-49136 allows unauthenticated attackers to read sensitive image-format files from arbitrary locations on the server. This could lead to the exposure of confidential data, including configuration files containing credentials, private keys, or other sensitive information. The CVSS v3.1 base score for this vulnerability is 7.5, indicating a high severity.

## Recommendation

*   Upgrade Banana Slides to a version greater than 0.4.0, which includes the patch from commit e8bc490, to remediate CVE-2026-49136.
*   Deploy the Sigma rule "Detect CVE-2026-49136 Exploitation Attempt - Path Traversal in Banana Slides" to your SIEM to detect exploitation attempts based on HTTP request patterns.
*   Review webserver access logs for requests containing path traversal sequences in the `cs-uri-query` or `cs-uri-stem` fields, specifically targeting image-related endpoints as identified in the vulnerability description.
