---
title: Insecure Deserialization Vulnerability in Telerik UI for AJAX RadFilter Control (CVE-2026-6023)
slug: 2026-04-telerik-rce
description: An insecure deserialization vulnerability exists in Progress Telerik UI for AJAX's RadFilter control (versions 2024.4.1114 through 2026.1.421) allowing remote code execution via tampering with the filter state exposed to the client.
date: "2026-04-22T08:16:13Z"
severities:
  - critical
tags:
  - cve-2026-6023
  - telerik
  - deserialization
  - rce
  - webserver
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
cves:
  - id: CVE-2026-6023
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6023
  - https://www.telerik.com/products/aspnet-ajax/documentation/knowledge-base/kb-security-deserialization-of-untrusted-data-cve-2026-6023
rules:
  - title: Detect Suspicious Telerik RadFilter Deserialization Attempt
    description: Detects suspicious HTTP requests potentially exploiting the Telerik RadFilter deserialization vulnerability (CVE-2026-6023) by identifying requests with unusual patterns in the query string or body.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
      - windows|linux
  - title: Detect Telerik RadFilter ViewState Tampering
    description: Detects potential ViewState tampering attempts in Telerik RadFilter, indicative of deserialization exploits.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1190
    data_sources:
      - webserver
      - windows|linux
rules_count: 2
---

CVE-2026-6023 exposes a critical vulnerability within the RadFilter control of Progress Telerik UI for AJAX. Affecting versions 2024.4.1114 to 2026.1.421, this flaw stems from insecure deserialization practices. The vulnerability arises when the filter state is exposed to the client, enabling malicious actors to manipulate this state. Successful exploitation grants attackers the ability to execute arbitrary code on the server. This vulnerability poses a significant risk to organizations…
