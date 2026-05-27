---
title: IBM Langflow OSS Remote Code Execution Vulnerability (CVE-2026-7524)
slug: 2026-05-ibm-langflow-rce
description: IBM Langflow OSS versions 1.0.0 through 1.9.1 are vulnerable to remote code execution (CVE-2026-7524) due to improper validation of symbolic links during archive extraction, potentially allowing an attacker to execute arbitrary code on the system.
date: "2026-05-27T14:18:28Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - cve-2026-7524
  - rce
  - path traversal
  - ibm langflow
vendors:
  - IBM
products:
  - Langflow OSS (1.0.0 - 1.9.1)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
cves:
  - id: CVE-2026-7524
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7524
  - https://www.ibm.com/support/pages/node/7273426
rules:
  - title: Detect Suspicious Archive Extraction via Langflow
    description: Detects CVE-2026-7524 exploitation attempt via archive extraction with path traversal
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Langflow Process Spawning Shell
    description: Detects processes spawned by Langflow that are shells
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

IBM Langflow OSS versions 1.0.0 through 1.9.1 are susceptible to a remote code execution vulnerability, identified as CVE-2026-7524. This flaw arises from the improper validation of symbolic links during archive extraction. An attacker could exploit this vulnerability to execute arbitrary code on the system, potentially leading to complete system compromise. This vulnerability was disclosed on May 27, 2026, and has a CVSS v3.1 base score of 9.8, indicating a critical severity. Successful exploitation requires no user interaction and can be performed remotely.

## Attack Chain

1.  The attacker crafts a malicious archive containing symbolic links.
2.  The attacker uploads the malicious archive to the Langflow server.
3.  Langflow extracts the archive without properly validating the symbolic links.
4.  The symbolic links point to locations outside the intended extraction directory.
5.  Files are created or overwritten in unintended locations due to path traversal.
6.  The attacker overwrites a critical system file with malicious code.
7.  The compromised system file is executed.
8.  The attacker achieves remote code execution on the Langflow server.

## Impact

Successful exploitation of CVE-2026-7524 can lead to complete compromise of the Langflow server. This includes the ability to execute arbitrary code, access sensitive data, and disrupt services. Given the critical severity and ease of exploitation (no user interaction required), organizations using affected versions of IBM Langflow OSS are at high risk. There are no specific details on the number of victims or sectors targeted available.

## Recommendation

*   Upgrade IBM Langflow OSS to a version beyond 1.9.1 to patch CVE-2026-7524.
*   Implement strict validation of symbolic links during archive extraction to prevent path traversal vulnerabilities as described in CWE-22.
*   Deploy the Sigma rule "Detect Suspicious Archive Extraction via Langflow" to identify potential exploitation attempts.
*   Monitor web server logs for unusual activity related to archive uploads and extractions on the Langflow server.
