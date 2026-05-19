---
title: Budibase Stored XSS Vulnerability via Unrestricted File Upload (CVE-2026-46426)
slug: 2026-05-budibase-xss
description: Budibase is vulnerable to persistent stored XSS (CVE-2026-46426) due to unrestricted file upload of active content by authenticated users, leading to potential session cookie theft and account takeover.
date: "2026-05-19T16:33:54Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xss
  - file-upload
  - budibase
  - cve-2026-46426
vendors:
  - Budibase
products:
  - budibase (< 3.38.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.001
    technique_name: 'Command and Scripting Interpreter: PowerShell'
references:
  - https://github.com/advisories/GHSA-82rc-gxrg-v4gf
  - CVE-2026-46426
rules:
  - title: Detect Budibase Suspicious SVG Upload
    description: Detects the upload of SVG files containing <script> tags to the Budibase /api/attachments/process endpoint, indicating potential XSS attempts related to CVE-2026-46426.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
  - title: Detect Budibase Attachment Request with SVG Extension
    description: Detects requests for SVG attachments within Budibase, potentially indicating exploitation of CVE-2026-46426.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
rules_count: 2
---

Budibase, a low-code platform, is susceptible to a stored cross-site scripting (XSS) vulnerability (CVE-2026-46426) affecting versions prior to 3.38.2. The vulnerability stems from the `/api/attachments/process` endpoint, which inadequately restricts the upload of files with dangerous content. Authenticated users with builder privileges can upload malicious files, such as SVG files containing inline JavaScript, HTML pages with embedded scripts, or JavaScript modules. These files are stored with correct MIME types in the object store (MinIO/S3). Subsequently, when any application user accesses a screen containing the URL of the uploaded file, the browser executes the malicious payload, potentially leading to session cookie theft and full account takeover. This issue impacts both application end-users and builder accounts.

## Attack Chain

1. The attacker authenticates to Budibase as a user with the Builder role via `POST /api/global/auth/default/login`.
2. The server responds with a JWT and CSRF token embedded within the session.
3. The attacker extracts the CSRF token from the session.
4. The attacker crafts a malicious SVG file containing an XSS payload, such as `<svg xmlns="http://www.w3.org/2000/svg"><script>alert(document.domain)</script></svg>`.
5. The attacker uploads the malicious SVG file to the `/api/attachments/process` endpoint using a `POST` request with the `Content-Type` set to `multipart/form-data` and including the CSRF token.
6. The server stores the SVG file in the object store (MinIO/S3) with the correct MIME type (`image/svg+xml`).
7. The server returns a JSON response containing the URL of the uploaded file, such as `http://target:10000/files/signed/.../<uuid>.svg?X-Amz-...`.
8. An end user accesses a screen within the Budibase application that includes the URL of the uploaded SVG file, causing the browser to execute the embedded JavaScript. This results in XSS.

## Impact

The vulnerability allows for persistent stored XSS on any screen displaying the attachment URL. Successful exploitation can lead to session cookie theft, resulting in full account takeover for application end-users. Furthermore, if a malicious URL is shared within the workspace, such as in a table attachment or embedded image, the XSS can fire in a builder's session, potentially leading to workspace takeover. The number of affected users depends on the scale of the Budibase application and the visibility of the malicious attachment.

## Recommendation

*   Upgrade Budibase to version 3.38.2 or later to patch CVE-2026-46426.
*   Deploy the Sigma rule "Detect Budibase Suspicious SVG Upload" to monitor for the upload of SVG files containing `<script>` tags.
*   Deploy the Sigma rule "Detect Budibase Attachment Request with SVG Extension" to monitor for requests to uploaded SVG attachments.
