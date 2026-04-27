---
title: openFPGALoader Heap-Buffer-Overflow Read Vulnerability
slug: 2026-04-openfpgaloader-heap-overflow
description: A heap-buffer-overflow read vulnerability exists in openFPGALoader 1.1.1 and earlier, allowing out-of-bounds heap memory access via a crafted .pof file, potentially leading to denial of service or information disclosure.
date: "2026-04-06T20:16:25Z"
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

openFPGALoader is a utility used for programming Field-Programmable Gate Arrays (FPGAs). A heap-buffer-overflow read vulnerability has been identified in versions 1.1.1 and earlier. The vulnerability, tracked as CVE-2026-35176, resides in the `POFParser::parseSection()` function. It allows an attacker to trigger out-of-bounds heap memory access by supplying a specially crafted `.pof` file. Critically, exploiting this vulnerability does not require any specific FPGA hardware, making it easier to…
