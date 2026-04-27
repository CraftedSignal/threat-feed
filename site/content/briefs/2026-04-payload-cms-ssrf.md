---
title: Payload CMS SSRF Vulnerability (CVE-2026-34746)
slug: 2026-04-payload-cms-ssrf
description: Payload CMS versions before 3.79.1 are vulnerable to Server-Side Request Forgery (SSRF) allowing authenticated users with upload access to trigger outbound HTTP requests to arbitrary URLs.
date: "2026-04-01T20:16:26Z"
severities:
  - medium
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

Payload CMS, a free and open-source headless content management system, is susceptible to a Server-Side Request Forgery (SSRF) vulnerability (CVE-2026-34746) in versions prior to 3.79.1. This flaw allows authenticated users with create or update permissions to upload-enabled collections to trigger the server to initiate outbound HTTP requests to arbitrary URLs. This vulnerability stems from insufficient validation of user-supplied URLs during the upload process. An attacker could potentially…
