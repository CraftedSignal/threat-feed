---
title: Payload CMS SSRF Vulnerability (CVE-2026-34746)
slug: 2026-04-payload-cms-ssrf
description: Payload CMS versions before 3.79.1 are vulnerable to Server-Side Request Forgery (SSRF) allowing authenticated users with upload access to trigger outbound HTTP requests to arbitrary URLs.
date: "2026-04-01T20:16:26Z"
severities:
  - medium
type: advisory
types:
  - advisory
tags:
  - cve-2026-34746
  - ssrf
  - payload-cms
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-34746
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34746
  - https://github.com/payloadcms/payload/releases/tag/v3.79.1
  - https://github.com/payloadcms/payload/security/advisories/GHSA-6r7f-q7f5-wpx8
rules:
  - title: Detect Outbound Connections from Payload CMS Web Server
    description: Detects outbound network connections originating from the Payload CMS web server, which could be indicative of SSRF exploitation.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - linux
  - title: Detect Suspicious File Uploads in Payload CMS
    description: Detects file uploads to the Payload CMS application with suspicious file extensions that could indicate an attempt to exploit SSRF.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - file_event
      - linux
rules_count: 2
---

Payload CMS, a free and open-source headless content management system, is susceptible to a Server-Side Request Forgery (SSRF) vulnerability (CVE-2026-34746) in versions prior to 3.79.1. This flaw allows authenticated users with create or update permissions to upload-enabled collections to trigger the server to initiate outbound HTTP requests to arbitrary URLs. This vulnerability stems from insufficient validation of user-supplied URLs during the upload process. An attacker could potentially exploit this to scan internal networks, access internal services, or conduct other malicious activities. The vulnerability has been addressed in version 3.79.1 of Payload CMS.

## Attack Chain

1. An attacker authenticates to the Payload CMS application with create or update access to an upload-enabled collection.
2. The attacker crafts a malicious request containing a URL intended for server-side processing via the upload functionality. This URL could point to an internal service, a file on the local system, or an external server controlled by the attacker.
3. The attacker submits the crafted request to the Payload CMS server through the upload mechanism.
4. The Payload CMS server, lacking adequate validation of the provided URL, processes the request.
5. The server initiates an HTTP request to the attacker-specified URL.
6. The server receives the response from the targeted URL.
7. The response is potentially processed or returned by the Payload CMS application depending on the specific implementation.
8. The attacker gains access to internal resources or services, or potentially uses the server as a proxy for further attacks.

## Impact

Successful exploitation of this SSRF vulnerability (CVE-2026-34746) can allow an attacker to perform unauthorized actions such as internal port scanning, accessing sensitive data from internal services, or leveraging the compromised server as a proxy to conduct attacks against other systems. This could lead to data breaches, service disruption, or further compromise of the affected infrastructure. Although the precise number of installations affected is unknown, organizations using versions of Payload CMS prior to 3.79.1 are vulnerable.

## Recommendation

*   Upgrade Payload CMS to version 3.79.1 or later to patch the SSRF vulnerability (CVE-2026-34746).
*   Implement strict input validation on all user-supplied URLs, especially those used in upload functionality, to prevent SSRF attacks.
*   Monitor web server logs for unusual outbound HTTP requests originating from the Payload CMS server to detect potential SSRF exploitation. Deploy the Sigma rule detecting outbound connections from the webserver.
*   Implement network segmentation to limit the impact of a successful SSRF attack by restricting access to sensitive internal resources.
