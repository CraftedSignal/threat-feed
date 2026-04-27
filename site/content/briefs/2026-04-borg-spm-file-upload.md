---
title: Borg SPM 2007 Arbitrary File Upload Vulnerability (CVE-2026-6885)
slug: 2026-04-borg-spm-file-upload
description: An unauthenticated remote attacker can exploit an arbitrary file upload vulnerability (CVE-2026-6885) in Borg SPM 2007 to upload and execute web shell backdoors, leading to arbitrary code execution on the server.
date: "2026-04-23T10:16:18Z"
severities:
  - critical
tags:
  - file-upload
  - web-shell
  - code-execution
vendors:
  - BorG Technology Corporation
products:
  - SPM 2007
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2026-6885
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6885
  - https://www.twcert.org.tw/en/cp-139-10863-2f48e-2.html
  - https://www.twcert.org.tw/tw/cp-132-10861-b8709-1.html
rules:
  - title: Detect Web Shell Upload via HTTP POST
    description: Detects potential web shell uploads by monitoring HTTP POST requests with common web shell file extensions.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Detect Access to Newly Uploaded Web Shell
    description: Detects access to recently uploaded files with web shell extensions, indicating potential exploitation of a file upload vulnerability.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Borg SPM 2007, a product by BorG Technology Corporation with sales ending in 2008, is vulnerable to arbitrary file uploads (CVE-2026-6885). This vulnerability allows unauthenticated remote attackers to upload malicious files, such as web shells, which can then be executed by the server. The attacker can then achieve arbitrary code execution, leading to a compromise of the system. Given the age of the software, it is likely running on outdated systems with fewer security controls making…
