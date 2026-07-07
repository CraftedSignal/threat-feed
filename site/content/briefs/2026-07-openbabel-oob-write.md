---
title: Open Babel MOL2 Parser Out-of-Bounds Write (CVE-2022-43607)
slug: 2026-07-openbabel-oob-write
description: A memory-safety vulnerability, CVE-2022-43607, in Open Babel's MOL2 parser allows an out-of-bounds write when processing a crafted input file, potentially leading to denial of service or arbitrary code execution.
date: "2026-07-03T12:52:17Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:openbabel:open_babel:3.1.1:*:*:*:*:*:*:*
tags:
  - memory-safety
  - vulnerability
  - library
  - cve
  - file-parsing
  - chemistry
  - denial-of-service
  - code-execution
vendors:
  - Open Babel
products:
  - Open Babel (up to 3.1.1)
  - openbabel (pip) (up to 3.1.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204
    technique_name: User Execution
    evidence: Triggering this vulnerability requires the victim to open a malicious MOL2 file with the `obabel` tool, the `OBConversion` API, or any of the language bindings (Python, Ruby, Java, R, Perl, C#, PHP).
    confidence_band: high
cves:
  - id: CVE-2022-43607
    cvss: 8.1
    epss: 0.00753
references:
  - https://github.com/advisories/GHSA-vjg6-gm8m-v5g6
  - https://github.com/openbabel/openbabel/commit/4110d59a
rules:
  - title: Detect Open Babel obabel CLI Processing MOL2 Files
    description: Detects the execution of the Open Babel command-line tool `obabel` when it is invoked to process .mol2 files, which is a known trigger for CVE-2022-43607.
    platform: sigma
    severity: low
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - linux
rules_count: 1
---

Cisco TALOS reported a critical memory-safety vulnerability, CVE-2022-43607, affecting Open Babel versions up to 3.1.1. This flaw resides within the MOL2 file format parser, specifically in the attribute/value parsing path. An attacker can craft a malicious MOL2 file containing an overly long attribute or value, which, when processed by the vulnerable Open Babel software, triggers an out-of-bounds write. This vulnerability is significant because Open Babel is a widely used C++ library and command-line interface (`obabel`) for manipulating chemistry file formats, often embedded in scientific applications and services. The vulnerability can be exploited when a victim opens a specially crafted MOL2 file using the `obabel` tool, the `OBConversion` API, or any of its language bindings (Python, Ruby, Java, R, Perl, C#, PHP). This can lead to memory corruption, denial of service, or potentially arbitrary code execution if successfully weaponized.

## Attack Chain

1.  An attacker crafts a malicious MOL2 file containing an over-long attribute or value designed to exceed a fixed-size buffer.
2.  The attacker delivers this crafted MOL2 file to a target system or user (e.g., via email, web download, or shared storage).
3.  The victim opens or processes the malicious MOL2 file using the `obabel` command-line tool, the `OBConversion` API, or one of Open Babel's language bindings.
4.  Open Babel's MOL2 parser attempts to parse the malicious file's attributes and values.
5.  During parsing, the overly long data triggers an out-of-bounds write operation past the end of an allocated memory buffer.
6.  This memory corruption can lead to a crash of the Open Babel process, resulting in a denial of service (DoS).
7.  With sophisticated exploitation, this memory corruption could potentially be leveraged to achieve arbitrary code execution.

## Impact

The successful exploitation of CVE-2022-43607 can result in memory corruption, leading to a denial of service (DoS) by crashing the application or tool processing the malicious MOL2 file. In more severe scenarios, it could enable arbitrary code execution, granting attackers control over the compromised system. While no specific in-the-wild exploitation has been observed, the widespread use of Open Babel in academic, research, and industrial sectors that handle chemical data means that a broad range of organizations could be affected. Any service or workstation that uses Open Babel to parse untrusted MOL2 files is at risk.

## Recommendation

*   Patch CVE-2022-43607 by updating Open Babel to version 3.2.0 or later immediately across all affected systems.
*   Implement process creation logging (e.g., Sysmon for Windows or Auditd for Linux) to activate the provided Sigma rule for `obabel` execution.
*   Review and tune the provided Sigma rule to monitor for unusual invocations of the `obabel` command-line tool, especially from untrusted sources or with uncommon parameters.
*   Educate users on the risks of opening untrusted or suspicious MOL2 files received from unknown sources, as user interaction is required for exploitation.
