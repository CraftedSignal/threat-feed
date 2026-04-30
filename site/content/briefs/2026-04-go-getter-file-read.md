---
title: HashiCorp go-getter Arbitrary File Read Vulnerability (CVE-2026-4660)
slug: 2026-04-go-getter-file-read
description: HashiCorp's go-getter library up to v1.8.5 is vulnerable to arbitrary file reads on the file system during certain git operations through a maliciously crafted URL (CVE-2026-4660), potentially allowing attackers to access sensitive information.
date: "2026-04-09T14:16:32Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - cve-2026-4660
  - file-read
  - go-getter
  - information-disclosure
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-4660
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4660
  - https://discuss.hashicorp.com/t/hcsec-2026-04-go-getter-may-allow-to-arbitrary-filesystem-reads-through-git-operations/77311
iocs:
  - type: url
    value: https://discuss.hashicorp.com/t/hcsec-2026-04-go-getter-may-allow-to-arbitrary-filesystem-reads-through-git-operations/77311
ioc_counts:
  url: 1
rules:
  - title: Detect Go-Getter Arbitrary File Read Attempt
    description: Detects potential attempts to exploit CVE-2026-4660 by monitoring process command lines for suspicious patterns indicative of arbitrary file read attempts using go-getter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - process_creation
      - linux
  - title: Detect Go-Getter Arbitrary File Read Attempt (Windows)
    description: Detects potential attempts to exploit CVE-2026-4660 by monitoring process command lines for suspicious patterns indicative of arbitrary file read attempts using go-getter on Windows systems.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

HashiCorp's go-getter library, a tool for retrieving files or directories from various sources, is susceptible to an arbitrary file read vulnerability (CVE-2026-4660) in versions up to 1.8.5. The vulnerability stems from insufficient validation of URLs during git operations, potentially allowing a malicious actor to craft a URL that, when processed by go-getter, results in the reading of arbitrary files from the system's file system. This could lead to the exposure of sensitive data, configuration files, or credentials. The vulnerability has been patched in go-getter version 1.8.6, and the go-getter/v2 branch is not affected. This vulnerability allows for information disclosure, with a CVSS v3.1 score of 7.5.

## Attack Chain

1.  The attacker crafts a malicious URL designed to exploit the go-getter library's git operation handling.
2.  The attacker delivers the malicious URL to a system running a vulnerable version of go-getter (<= 1.8.5). The specific delivery mechanism is not defined in the source material.
3.  The go-getter library processes the URL, attempting to retrieve files as instructed.
4.  Due to insufficient URL validation, the go-getter library is tricked into accessing arbitrary files on the system.
5.  The content of the accessed files is read by the go-getter library.
6.  The attacker retrieves the contents of the file through the go-getter library.
7.  The attacker gains access to potentially sensitive information contained within the accessed file.
8.  The attacker leverages the disclosed information for further malicious activities, such as privilege escalation or lateral movement.

## Impact

Successful exploitation of CVE-2026-4660 allows an attacker to read arbitrary files on the system where the vulnerable go-getter library is running. This can lead to the disclosure of sensitive information, including configuration files, credentials, source code, or other confidential data. The number of potential victims is dependent on the widespread adoption of the go-getter library across various systems and applications. The impact is significant as it allows for unauthorized access to sensitive data, potentially leading to further compromise of the affected system and network.

## Recommendation

*   Upgrade the go-getter library to version 1.8.6 or later to remediate CVE-2026-4660.
*   Implement input validation and sanitization on URLs processed by the go-getter library, focusing on git operations to prevent similar vulnerabilities.
*   Monitor network traffic for suspicious URL patterns that may indicate exploitation attempts targeting CVE-2026-4660. While no specific network IOCs are provided, generic webserver rules may be helpful.
*   Deploy the Sigma rule `Detect Go-Getter Arbitrary File Read Attempt` to identify potential exploitation attempts based on suspicious process command-line arguments.
