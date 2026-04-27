---
title: HashiCorp go-getter Arbitrary File Read Vulnerability (CVE-2026-4660)
slug: 2026-04-go-getter-file-read
description: HashiCorp's go-getter library up to v1.8.5 is vulnerable to arbitrary file reads on the file system during certain git operations through a maliciously crafted URL (CVE-2026-4660), potentially allowing attackers to access sensitive information.
date: "2026-04-09T14:16:32Z"
severities:
  - high
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

HashiCorp's go-getter library, a tool for retrieving files or directories from various sources, is susceptible to an arbitrary file read vulnerability (CVE-2026-4660) in versions up to 1.8.5. The vulnerability stems from insufficient validation of URLs during git operations, potentially allowing a malicious actor to craft a URL that, when processed by go-getter, results in the reading of arbitrary files from the system's file system. This could lead to the exposure of sensitive data…
