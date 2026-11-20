---
brief_id: brief-2026-03-25-pdf-image-command-injection
event_id: brief-2026-03-25-pdf-image-command-injection
revision: 2
activity_at: "2026-11-20T04:38:22Z"
revision_history:
  - revision: 2
    at: "2026-11-20T04:38:22Z"
    checksum: sha256:9f5d44d22859b605c1eede627c0cc5d510a03297776e221e4125f649ad0213ca
    summary: poc_available; added CVE-2026-26830
    changed_fields:
      - affected_vendors
      - cpes
      - cves
      - has_poc
      - iocs
      - lastmod
      - poc_references
      - references
      - ttps
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-ZEBBERNCVE-CVE-2026-26830&utm_source=rss&utm_medium=rss
title: pdf-image npm Package Command Injection Vulnerability (CVE-2026-26830)
slug: 2026-03-pdf-image-command-injection
description: The pdf-image npm package through version 2.0.0 is vulnerable to OS command injection via the pdfFilePath parameter due to improper sanitization, potentially leading to arbitrary code execution.
date: "2026-03-25T15:16:38Z"
lastmod: "2026-11-20T04:37:55Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
cpes:
  - cpe:2.3:a:pdf-image_project:pdf-image:*:*:*:*:*:node.js:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-ZEBBERNCVE-CVE-2026-26830&utm_source=rss&utm_medium=rss
tags:
  - command-injection
  - npm
  - CVE-2026-26830
  - pdf
vendors:
  - mooz
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.004
    subtechnique_name: Unix Shell
cves:
  - id: CVE-2026-26830
    cvss: 9.8
    epss: 0.0256
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-26830
  - https://github.com/mooz/node-pdf-image
  - https://github.com/zebbernCVE/CVE-2026-26830
  - https://www.npmjs.com/package/pdf-image
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-ZEBBERNCVE-CVE-2026-26830&utm_source=rss&utm_medium=rss
rules:
  - title: Detect Suspicious PDF Image Command Execution
    description: Detects potential command injection attempts in pdf-image library by monitoring for suspicious child processes spawned by node processes.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Suspicious PDF Image Network Connection
    description: Detects potential command injection attempts in pdf-image library by monitoring for suspicious outbound network connections from node processes after pdf processing.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - linux
rules_count: 2
updates:
  - at: "2026-11-20T04:37:55Z"
    level: L2
    summary: poc_available; added CVE-2026-26830
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-ZEBBERNCVE-CVE-2026-26830&utm_source=rss&utm_medium=rss
---

## Overview

The pdf-image npm package, up to version 2.0.0, contains a critical vulnerability (CVE-2026-26830) that allows for OS command injection. This vulnerability stems from the way the package handles user-provided file paths when processing PDF files. Specifically, the `constructGetInfoCommand` and `constructConvertCommandForPage` functions utilize `util.format()` to incorporate the `pdfFilePath` parameter directly into shell command strings. These commands are then executed using `child_process.exec()`, allowing an attacker to inject arbitrary commands into the system. This vulnerability poses a significant risk to applications that rely on this package to handle untrusted PDF files.

## Attack Chain

1.  An attacker crafts a malicious PDF file with a specially crafted file name or path.
2.  The vulnerable application using the `pdf-image` library receives the path to the malicious PDF file as input via the `pdfFilePath` parameter.
3.  The application calls either `constructGetInfoCommand` or `constructConvertCommandForPage` functions within the `pdf-image` library to process the PDF file.
4.  The `constructGetInfoCommand` or `constructConvertCommandForPage` function uses `util.format()` to interpolate the attacker-controlled `pdfFilePath` into a shell command string, without proper sanitization.
5.  The resulting command string contains injected OS commands and is passed to `child_process.exec()`.
6.  `child_process.exec()` executes the command string, including the injected OS commands.
7.  The attacker's injected commands are executed with the privileges of the Node.js process.
8.  The attacker achieves arbitrary code execution on the server, potentially leading to data exfiltration, system compromise, or denial of service.

## Impact

Successful exploitation of this vulnerability can lead to arbitrary code execution on the server hosting the vulnerable application. This could result in a full system compromise, allowing attackers to steal sensitive data, install malware, or disrupt services. Given the widespread use of npm packages, a successful attack could potentially impact a large number of applications and users. A CVSS v3.1 score of 9.8 (Critical) highlights the severity and potential impact of this vulnerability.

## Recommendation

*   Upgrade the `pdf-image` npm package to a patched version that properly sanitizes user-provided file paths to prevent command injection.
*   Implement strict input validation on the `pdfFilePath` parameter to prevent malicious file names or paths from being processed by the vulnerable functions.
*   Deploy the Sigma rule `Detect Suspicious PDF Image Command Execution` to identify potential exploitation attempts by monitoring for suspicious processes spawned by Node.js child processes.
*   Review and audit all code that utilizes the `pdf-image` package to ensure proper handling of user-provided file paths.
