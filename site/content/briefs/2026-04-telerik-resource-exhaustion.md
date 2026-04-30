---
title: Telerik UI for AJAX RadAsyncUpload Uncontrolled Resource Consumption (CVE-2026-6022)
slug: 2026-04-telerik-resource-exhaustion
description: A vulnerability exists in Progress Telerik UI for AJAX prior to 2026.1.421, RadAsyncUpload, due to missing cumulative size enforcement during chunk reassembly, which allows file uploads to exceed the configured maximum size, leading to disk space exhaustion.
date: "2026-04-22T08:16:12Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve-2026-6022
  - telerik
  - resource-exhaustion
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-6022
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6022
  - https://www.telerik.com/products/aspnet-ajax/documentation/knowledge-base/kb-security-uncontrolled-resource-consumption-cve-2026-6022
rules:
  - title: Detect Suspicious RadAsyncUpload Chunks
    description: Detects suspicious activity related to RadAsyncUpload by monitoring for a high number of chunk uploads within a short timeframe, potentially indicating an attempt to bypass file size limits.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1499.004
    data_sources:
      - webserver
      - windows
  - title: Detect Large File Upload via Telerik RadAsyncUpload
    description: Detects unusually large file uploads through the Telerik RadAsyncUpload component, which could indicate an attempt to exploit CVE-2026-6022.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1499.004
    data_sources:
      - webserver
      - windows
rules_count: 2
---

Progress Telerik UI for AJAX, a suite of UI components for ASP.NET AJAX, contains an uncontrolled resource consumption vulnerability within the RadAsyncUpload component. This vulnerability, identified as CVE-2026-6022, affects versions prior to 2026.1.421. The vulnerability stems from a failure to properly enforce maximum file size limits during the reassembly of file chunks uploaded via the RadAsyncUpload component. An unauthenticated attacker could exploit this vulnerability by uploading a large file in chunks, bypassing the configured maximum file size restriction. Successful exploitation leads to excessive disk space consumption on the server, potentially causing denial of service.

## Attack Chain

1.  The attacker identifies a web application using a vulnerable version of Progress Telerik UI for AJAX with the RadAsyncUpload component enabled.
2.  The attacker crafts an HTTP request to initiate a file upload to the RadAsyncUpload endpoint.
3.  The attacker splits the malicious file into multiple chunks, each smaller than the initially configured maximum upload size limit.
4.  The attacker sends each chunk to the server using separate HTTP requests to the RadAsyncUpload endpoint.
5.  The server receives the chunks and stores them temporarily, without enforcing the cumulative file size.
6.  Once all chunks are uploaded, the RadAsyncUpload component reassembles the file.
7.  Due to the missing cumulative size check, the reassembled file exceeds the maximum allowed file size.
8.  The server stores the complete, oversized file, leading to disk space exhaustion.

## Impact

Successful exploitation of this vulnerability can lead to a denial-of-service condition due to disk space exhaustion. The number of affected systems depends on the usage of the vulnerable Telerik UI for AJAX RadAsyncUpload component. Organizations in any sector using the affected Telerik component are potentially vulnerable. If successful, the attack can cause application downtime, data loss, and require administrative intervention to restore service.

## Recommendation

*   Upgrade Progress Telerik UI for AJAX to version 2026.1.421 or later to patch CVE-2026-6022.
*   Implement server-side monitoring for excessive disk space usage in directories associated with RadAsyncUpload temporary file storage.
*   Deploy the Sigma rule `DetectSuspiciousRadAsyncUploadChunks` to detect potential exploitation attempts.
*   Review and harden file upload size limits to prevent resource exhaustion, as described in the Telerik documentation referenced.
