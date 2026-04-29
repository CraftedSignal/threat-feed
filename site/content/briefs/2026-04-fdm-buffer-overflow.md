---
title: Free Download Manager 2.0 Built 417 Local Buffer Overflow Vulnerability
slug: 2026-04-fdm-buffer-overflow
description: Free Download Manager 2.0 Built 417 contains a local buffer overflow vulnerability in the URL import functionality that allows attackers to trigger a structured exception handler (SEH) chain exploitation, leading to arbitrary code execution.
date: "2026-04-29T20:16:25Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - buffer-overflow
  - seh-overwrite
  - code-execution
  - cve-2018-25304
vendors:
  - Free Download Manager
products:
  - Free Download Manager 2.0
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
cves:
  - id: CVE-2018-25304
    cvss: 8.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25304
  - https://filehippo.com/download_free_download_manager/925/
  - https://www.exploit-db.com/exploits/44499
  - https://www.vulncheck.com/advisories/free-download-manager-built-417-local-buffer-overflow-seh
rules:
  - title: Detect Free Download Manager Suspicious Process Creation After Import
    description: Detects suspicious process creation events originating from Free Download Manager after a .url file import, indicating potential exploitation of CVE-2018-25304.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059
      - T1218
      - T1547
    data_sources:
      - process_creation
      - windows
  - title: Detect Free Download Manager Suspicious File Access After Import
    description: Detects suspicious file access events originating from Free Download Manager after a .url file import, indicating potential exploitation of CVE-2018-25304.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059
      - T1218
      - T1547
    data_sources:
      - file_event
      - windows
rules_count: 2
---

Free Download Manager (FDM) version 2.0 Built 417 is susceptible to a local buffer overflow vulnerability (CVE-2018-25304) within its URL import functionality. This vulnerability, discovered and reported by VulnCheck, allows an attacker to craft a malicious URL file. When a user imports this specially crafted file through the "File > Import > Import lists of downloads" menu, the application attempts to process the 'Location' header response, triggering a buffer overflow. This overflow overwrites the Structured Exception Handler (SEH) chain, enabling the attacker to execute arbitrary code within the context of the FDM process. This vulnerability can be exploited locally by tricking a user into importing a malicious file.

## Attack Chain

1.  Attacker crafts a malicious `.url` file containing an overly long `Location` header value designed to cause a buffer overflow.
2.  The victim is convinced to download the malicious `.url` file (e.g., through social engineering).
3.  The victim opens Free Download Manager 2.0 Built 417.
4.  The victim navigates to "File > Import > Import lists of downloads" within FDM.
5.  The victim selects the downloaded malicious `.url` file and initiates the import process.
6.  FDM parses the malicious `.url` file and attempts to process the long `Location` header.
7.  The excessively long `Location` header causes a buffer overflow, overwriting the SEH chain.
8.  When an exception is triggered (due to the overflow), the overwritten SEH chain is used to redirect execution to attacker-controlled code, resulting in arbitrary code execution.

## Impact

Successful exploitation of this buffer overflow vulnerability allows an attacker to execute arbitrary code on the victim's system with the privileges of the Free Download Manager process. This could lead to complete system compromise, data theft, or installation of malware. While specific victim counts are unavailable, the vulnerability poses a significant risk to users of Free Download Manager 2.0 Built 417.

## Recommendation

*   Monitor for process creation events originating from Free Download Manager after importing a `.url` file to detect potential exploitation attempts (see Sigma rule "Detect Free Download Manager Suspicious Process Creation After Import").
*   Implement file integrity monitoring (FIM) on the Free Download Manager executable directory to detect unauthorized modifications potentially related to exploitation.
*   Consider using application control solutions to restrict the execution of unsigned or untrusted code within the Free Download Manager process.
