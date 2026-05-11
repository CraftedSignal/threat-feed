---
title: MantisBT Private Bugnote Attachment Content Leak via REST API
slug: 2026-05-mantisbt-auth-bypass
description: MantisBT is vulnerable to a missing authorization check in its file visibility function, allowing authenticated users with REPORTER or higher access to download attachments on private bugnotes they should not be able to access through the REST API and SOAP API, affecting versions 2.23.0 to 2.28.1.
date: "2026-05-11T19:40:12Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - authorization-bypass
  - rest-api
vendors:
  - MantisBT
products:
  - mantisbt (>= 2.23.0, <= 2.28.1)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1539
    technique_name: Steal Web Session Cookie
references:
  - https://github.com/advisories/GHSA-pw5x-2mf9-3xc8
  - CVE-2026-42071
rules:
  - title: Detect CVE-2026-42071 Exploitation — MantisBT Private Bugnote Attachment Access via REST API
    description: Detects CVE-2026-42071 exploitation — Access to the MantisBT REST API endpoint for issue files without proper authorization.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1539
    data_sources:
      - webserver
  - title: Detect CVE-2026-42071 Exploitation — MantisBT Private Bugnote Attachment Access via SOAP API
    description: Detects CVE-2026-42071 exploitation — Usage of the MantisBT SOAP API function mc_issue_attachment_get without proper authorization.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1539
    data_sources:
      - webserver
rules_count: 2
---

MantisBT versions 2.23.0 through 2.28.1 are susceptible to an authorization bypass vulnerability (CVE-2026-42071) affecting the REST and SOAP APIs. A missing authorization check in the file visibility function allows any authenticated user with REPORTER access level or higher to download attachments on private bugnotes. These private bugnotes are intended for internal developer discussions, and their attachments (logs, screenshots, patches) should be equally protected. This issue was discovered and responsibly reported by multiple security researchers, including Vishal Shukla, Tristan Madani (@TristanInSec) from Talence Security, and Tang Cheuk Hei (@siunam321). The web UI is not affected by this vulnerability.

## Attack Chain

1. An attacker authenticates to the MantisBT instance with REPORTER or higher access.
2. The attacker identifies the ID of a bug issue.
3. The attacker uses the REST API endpoint `GET /api/rest/issues/{id}/files` or the SOAP API endpoint `mc_issue_attachment_get` to request attachments associated with the issue.
4. The API endpoint fails to properly validate whether the authenticated user has permission to access attachments associated with private bugnotes within that issue.
5. The attacker receives a list of attachment metadata, including file names and download URLs, associated with private bugnotes.
6. The attacker uses the download URLs to retrieve the contents of attachments on private bugnotes.
7. The attacker gains access to sensitive information contained within the attachments, such as logs, screenshots, or patches related to internal development discussions.

## Impact

Successful exploitation of this vulnerability allows low-privileged authenticated users (REPORTER+) to access sensitive information intended for internal developer discussion, potentially leading to information disclosure. Attachments may contain sensitive data such as logs, screenshots, or patches, compromising the confidentiality of internal development processes. The number of affected installations is unknown, but all MantisBT instances running versions 2.23.0 to 2.28.1 are potentially vulnerable.

## Recommendation

*   Upgrade MantisBT to a patched version beyond 2.28.1 to address CVE-2026-42071.
*   Deploy the Sigma rules provided below to your SIEM to detect potential exploitation attempts targeting the vulnerable REST API endpoint.
*   Monitor web server logs for unusual activity targeting the `/api/rest/issues/{id}/files` endpoint to identify potential exploit attempts.
