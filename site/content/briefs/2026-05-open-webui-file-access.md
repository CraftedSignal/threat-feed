---
title: Open WebUI Missing Permission Check Allows Unauthorized File Access and Deletion
slug: 2026-05-open-webui-file-access
description: Open WebUI versions 0.3.15 and earlier contain a missing permission check in the files API, allowing authenticated users to list, access, and delete files uploaded by any user on the platform, leading to a breach of confidentiality and integrity.
date: "2026-05-14T20:17:47Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - privilege-escalation
  - data breach
  - web application
  - file access
vendors:
  - open-webui
products:
  - open-webui (<= 0.3.15)
affected_os:
  - Ubuntu
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
references:
  - https://github.com/advisories/GHSA-r8wh-8m7r-fh33
  - CVE-2026-45301
rules:
  - title: Detect CVE-2026-45301 Exploitation — Unauthorized File Content Access via Open WebUI
    description: Detects CVE-2026-45301 exploitation — Unauthorized access to file content via the /api/v1/files/{id}/content endpoint in Open WebUI.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - webserver
  - title: Detect CVE-2026-45301 Exploitation — Unauthorized File Deletion via Open WebUI
    description: Detects CVE-2026-45301 exploitation — Unauthorized file deletion via the /api/v1/files/{id} endpoint in Open WebUI.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - webserver
rules_count: 2
---

Open WebUI, a web interface for interacting with language models, is vulnerable to a critical flaw affecting versions 0.3.15 and earlier. The vulnerability stems from a missing permission check within the application's file API endpoints. This oversight allows any authenticated user, regardless of their intended privileges, to list, access, and delete files uploaded by other users. The issue arises because the `/files/` related endpoints lack proper authorization mechanisms, failing to verify if the requesting user has the right to interact with the specified file. This enables malicious actors or disgruntled users to potentially exfiltrate sensitive information or disrupt the service by deleting critical files, causing significant data breaches or operational disruptions. The vulnerability was reported on May 14, 2026.

## Attack Chain

1. An attacker authenticates to the Open WebUI platform with a valid user account.
2. The attacker sends a GET request to `/api/v1/files/` to list all files uploaded to the platform. The API endpoint does not validate if the user has permission to list files owned by other users.
3. The API returns a JSON list of all files, including their IDs, filenames, user IDs, and paths on the server.
4. The attacker identifies a target file belonging to another user from the listing.
5. The attacker sends a GET request to `/api/v1/files/{id}/content` to access the content of the target file, replacing `{id}` with the file's ID. The API fails to verify if the user has permission to access the file.
6. The API returns the content of the target file to the attacker.
7. Alternatively, the attacker sends a DELETE request to `/api/v1/files/{id}` to delete the target file, again replacing `{id}` with the file's ID. The API also fails to validate deletion permissions.
8. The API successfully deletes the file, and the attacker can verify this by re-listing the files. The attacker achieves unauthorized access to files and/or deletes them.

## Impact

Successful exploitation of this vulnerability leads to a complete breach of confidentiality and integrity. An attacker can access sensitive data contained within user-uploaded files, potentially including personal information, financial records, or intellectual property. The attacker can also delete any file on the system, leading to data loss and service disruption. The number of affected users is proportional to the user base of the Open WebUI instance. The vulnerability could impact various sectors, including organizations using Open WebUI for internal knowledge management, document sharing, or customer support.

## Recommendation

*   Apply the patch released by Open WebUI to address the missing permission checks in the files API (reference: GHSA-r8wh-8m7r-fh33).
*   Deploy the provided Sigma rule to detect unauthorized access to the `/api/v1/files/{id}/content` endpoint.
*   Deploy the provided Sigma rule to detect unauthorized DELETE requests to the `/api/v1/files/{id}` endpoint.
*   Implement strict access control policies to limit which users can access specific API endpoints related to file management.
*   Review the Open WebUI codebase for similar missing permission checks in other API endpoints.
