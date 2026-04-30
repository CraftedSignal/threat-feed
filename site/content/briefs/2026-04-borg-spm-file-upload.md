---
title: Borg SPM 2007 Arbitrary File Upload Vulnerability (CVE-2026-6885)
slug: 2026-04-borg-spm-file-upload
description: An unauthenticated remote attacker can exploit an arbitrary file upload vulnerability (CVE-2026-6885) in Borg SPM 2007 to upload and execute web shell backdoors, leading to arbitrary code execution on the server.
date: "2026-04-23T10:16:18Z"
type: advisory
types:
  - advisory
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

Borg SPM 2007, a product by BorG Technology Corporation with sales ending in 2008, is vulnerable to arbitrary file uploads (CVE-2026-6885). This vulnerability allows unauthenticated remote attackers to upload malicious files, such as web shells, which can then be executed by the server. The attacker can then achieve arbitrary code execution, leading to a compromise of the system. Given the age of the software, it is likely running on outdated systems with fewer security controls making successful exploitation highly probable. This poses a significant risk to organizations still using this software.

## Attack Chain

1.  The attacker identifies a Borg SPM 2007 server exposed to the internet.
2.  The attacker sends a crafted HTTP POST request to the server, exploiting the file upload vulnerability (CVE-2026-6885).
3.  The POST request contains a malicious file, such as a PHP web shell, disguised with a permissible extension or without any extension check.
4.  The Borg SPM 2007 server saves the uploaded file to a publicly accessible directory, without proper sanitization.
5.  The attacker sends another HTTP request to access the uploaded web shell.
6.  The web server executes the web shell code, granting the attacker arbitrary code execution on the server.
7.  The attacker uses the web shell to gain a persistent foothold, install malware, or exfiltrate sensitive data.

## Impact

Successful exploitation of this vulnerability allows an unauthenticated remote attacker to execute arbitrary code on the vulnerable server. This can lead to full system compromise, data theft, and potential disruption of services. While the number of active installations is likely low due to the product's end-of-life status in 2008, organizations still running Borg SPM 2007 are at high risk if the system is exposed to the Internet.

## Recommendation

*   Identify instances of Borg SPM 2007 running in your environment and isolate them from the network if possible.
*   Implement the provided Sigma rule to detect potential web shell uploads based on HTTP request characteristics.
*   Since no patch exists, consider immediate decommissioning or migration to a supported alternative.
