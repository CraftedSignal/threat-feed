---
title: Telerik UI for AJAX RadAsyncUpload Uncontrolled Resource Consumption (CVE-2026-6022)
slug: 2026-04-telerik-resource-exhaustion
description: A vulnerability exists in Progress Telerik UI for AJAX prior to 2026.1.421, RadAsyncUpload, due to missing cumulative size enforcement during chunk reassembly, which allows file uploads to exceed the configured maximum size, leading to disk space exhaustion.
date: "2026-04-22T08:16:12Z"
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

Progress Telerik UI for AJAX, a suite of UI components for ASP.NET AJAX, contains an uncontrolled resource consumption vulnerability within the RadAsyncUpload component. This vulnerability, identified as CVE-2026-6022, affects versions prior to 2026.1.421. The vulnerability stems from a failure to properly enforce maximum file size limits during the reassembly of file chunks uploaded via the RadAsyncUpload component. An unauthenticated attacker could exploit this vulnerability by uploading a…
