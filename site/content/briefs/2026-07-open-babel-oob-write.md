---
title: Open Babel Out-of-Bounds Write Vulnerability (CVE-2022-37331)
slug: 2026-07-open-babel-oob-write
description: A memory-safety vulnerability (CVE-2022-37331) in Open Babel's Gaussian output parser allows for an out-of-bounds write when processing a specially crafted input file, potentially leading to denial of service or arbitrary code execution if a victim opens a malicious Gaussian output file with an affected tool or library version prior to 3.2.0.
date: "2026-07-03T12:55:30Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:openbabel:open_babel:3.1.1:*:*:*:*:*:*:*
tags:
  - vulnerability
  - memory-safety
  - out-of-bounds-write
  - client-side-exploitation
  - library-vulnerability
  - chemistry
vendors:
  - Open Babel
products:
  - Open Babel < 3.2.0
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: Triggering this vulnerability requires the victim to open a malicious Gaussian output file with the `obabel` tool, the `OBConversion` API, or any of the language bindings.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: Triggering this vulnerability requires the victim to open a malicious Gaussian output file with the `obabel` tool, the `OBConversion` API, or any of the language bindings.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This flaw... caused the parser to write past the end of its destination buffer... potentially leading to denial of service or arbitrary code execution.
    confidence_band: med
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Triggering this vulnerability... potentially leading to denial of service or arbitrary code execution.
    confidence_band: high
cves:
  - id: CVE-2022-37331
    cvss: 7.3
    epss: 0.00666
references:
  - https://github.com/advisories/GHSA-vr3p-gg26-45v9
  - https://github.com/openbabel/openbabel/commit/528c142f
---

A critical memory-safety vulnerability, tracked as CVE-2022-37331, has been identified in Open Babel, a widely used C++ chemistry library and command-line interface. Reported by Cisco TALOS, this flaw exists specifically within the `coords_type` orientation parser of the Gaussian output reader. Attackers can exploit this by crafting a malicious Gaussian output file containing a malformed orientation block. When a victim processes this file using an affected Open Babel tool (such as `obabel`), the `OBConversion` API, or any of its language bindings (Python, Ruby, Java, etc.), the parser attempts to write beyond its allocated buffer, resulting in an out-of-bounds write. This can lead to application crashes (denial of service) or potentially arbitrary code execution, enabling attackers to compromise the system. All Open Babel releases up to and including version 3.1.1 are affected. The vulnerability was patched in version 3.2.0, released on 2026-05-26.

## Attack Chain

1.  Attacker crafts a malicious Gaussian output file specifically designed with a malformed `coords_type` orientation block.
2.  Attacker delivers the malicious Gaussian output file to a target system, typically via social engineering (e.g., email attachment, malicious download link).
3.  The victim user opens or processes the malicious file using an affected Open Babel tool, such as the `obabel` command-line utility or a custom application utilizing the `OBConversion` API or its language bindings (e.g., Python, R, Java).
4.  During the file parsing process, the vulnerable `coords_type` orientation parser in Open Babel attempts to interpret the malformed data.
5.  Due to the malformed input, the parser performs an out-of-bounds write operation, attempting to write data past the intended boundary of its destination buffer.
6.  This memory corruption can immediately trigger a crash of the Open Babel application or the embedding service, leading to a denial-of-service condition.
7.  In more sophisticated exploitation scenarios, the out-of-bounds write could be leveraged to achieve arbitrary code execution on the victim's system.

## Impact

This vulnerability poses a significant risk to systems that process untrusted chemical file formats using Open Babel. Open Babel is integrated into various applications and Linux distributions, meaning many services could be susceptible. Successful exploitation could lead to denial of service, causing critical chemistry-related applications or services to crash, or, more severely, arbitrary code execution, allowing attackers to gain control over the compromised system. While the exact number of victims is not specified, the widespread use of Open Babel suggests a broad potential impact across academic, research, and industrial sectors utilizing chemical modeling and data processing.

## Recommendation

*   Prioritize patching Open Babel to version 3.2.0 or later immediately to address CVE-2022-37331 as described in the overview.
*   Educate users on the risks of opening unsolicited or untrusted Gaussian output files, as outlined in the Attack Chain.
*   Implement application whitelisting to restrict the execution of `obabel` or other applications linked against Open Babel versions prior to 3.2.0.
*   Monitor systems for unexpected crashes or unusual process behavior in applications that utilize Open Babel, which could indicate attempts to exploit CVE-2022-37331.
