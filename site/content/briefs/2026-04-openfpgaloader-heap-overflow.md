---
title: openFPGALoader Heap-Buffer-Overflow Read Vulnerability
slug: 2026-04-openfpgaloader-heap-overflow
description: A heap-buffer-overflow read vulnerability exists in openFPGALoader 1.1.1 and earlier, allowing out-of-bounds heap memory access via a crafted .pof file, potentially leading to denial of service or information disclosure.
date: "2026-04-06T20:16:25Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - heap-buffer-overflow
  - openFPGALoader
  - denial-of-service
  - information-disclosure
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Exploitation for Information Discovery
cves:
  - id: CVE-2026-35176
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35176
  - https://github.com/trabucayre/openFPGALoader/security/advisories/GHSA-9x7m-m8gv-px2j
rules:
  - title: Detect openFPGALoader POF Parsing with Unusual Process Arguments
    description: Detects the execution of openFPGALoader with .pof files, potentially indicating exploitation attempts of CVE-2026-35176.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1027
    data_sources:
      - process_creation
      - linux
  - title: Detect suspicious file creation of .pof files
    description: Detects the creation of .pof files in world-writable directories.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - file_event
      - linux
rules_count: 2
---

openFPGALoader is a utility used for programming Field-Programmable Gate Arrays (FPGAs). A heap-buffer-overflow read vulnerability has been identified in versions 1.1.1 and earlier. The vulnerability, tracked as CVE-2026-35176, resides in the `POFParser::parseSection()` function. It allows an attacker to trigger out-of-bounds heap memory access by supplying a specially crafted `.pof` file. Critically, exploiting this vulnerability does not require any specific FPGA hardware, making it easier to trigger. Successful exploitation could lead to denial of service or information disclosure.

## Attack Chain

1. An attacker crafts a malicious `.pof` file designed to trigger the heap-buffer-overflow.
2. The attacker delivers the malicious `.pof` file to a system running a vulnerable version of openFPGALoader (<= 1.1.1).
3. A user or automated process attempts to parse the malicious `.pof` file using openFPGALoader.
4. The `POFParser::parseSection()` function is called to process a section of the `.pof` file.
5. Due to the crafted structure of the `.pof` file, the `parseSection()` function attempts to read beyond the allocated heap buffer.
6. This out-of-bounds read operation causes the program to potentially crash (denial of service) or leak sensitive information from adjacent memory locations.
7. If information disclosure occurs, the attacker may gain insights into the system's memory layout or potentially extract sensitive data.

## Impact

Successful exploitation of this vulnerability can lead to a denial-of-service condition, causing the openFPGALoader application to crash. In certain scenarios, it might also be possible to read sensitive information from the application's memory space. While the exact scope of information disclosure is dependent on memory layout, the vulnerability poses a risk to systems using vulnerable versions of openFPGALoader. The risk is primarily to development environments using this tool rather than production FPGA deployments.

## Recommendation

*   Upgrade openFPGALoader to a version greater than 1.1.1 to patch CVE-2026-35176.
*   Deploy the Sigma rule "Detect openFPGALoader POF Parsing with Unusual Process Arguments" to your SIEM to identify potential exploitation attempts involving the execution of openFPGALoader with `.pof` files.
*   Monitor file system events for the creation or modification of `.pof` files in unusual locations to detect potential attempts to introduce malicious files into the system.
