---
title: .NET Spoofing Vulnerability (CVE-2026-32178)
slug: 2026-04-dotnet-spoofing
description: CVE-2026-32178 is a vulnerability in .NET that allows for network spoofing due to improper neutralization of special elements, potentially enabling attackers to impersonate legitimate entities.
date: "2026-04-14T18:17:20Z"
severities:
  - medium
tags:
  - dotnet
  - spoofing
  - cve-2026-32178
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-32178
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32178
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-32178
ioc_counts:
  email: 1
  url: 1
rules:
  - title: Detect Potential .NET Spoofing Attempts via Network Request
    description: Detects suspicious network requests indicative of CVE-2026-32178 exploitation attempts targeting .NET applications by looking for unusual characters or patterns in HTTP request parameters.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - windows
  - title: Detect Potential .NET Spoofing Attempts via URL
    description: Detects suspicious network requests indicative of CVE-2026-32178 exploitation attempts targeting .NET applications by looking for unusual characters or patterns in URLs.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - windows
rules_count: 2
---

CVE-2026-32178 is a security vulnerability affecting .NET applications. This vulnerability stems from the improper neutralization of special elements, which can be exploited by an unauthorized attacker to perform spoofing attacks over a network. Successful exploitation of this vulnerability could allow an attacker to impersonate trusted entities or services, potentially leading to unauthorized access, data manipulation, or other malicious activities. The vulnerability was published on April 14…
