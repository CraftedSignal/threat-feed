---
title: Open Babel Uninitialized Pointer Dereference Vulnerability (CVE-2022-42885)
slug: 2026-07-open-babel-uninitialized-ptr-deref
description: A high-severity memory-safety vulnerability (CVE-2022-42885) in Open Babel's GRO residue parser allows an uninitialized pointer dereference when processing a specially crafted GRO input file, potentially leading to application crash or arbitrary code execution.
date: "2026-07-03T12:54:02Z"
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
  - cve
  - open-babel
vendors:
  - Open Babel
products:
  - Open Babel <= 3.1.1
  - openbabel (pip) < 3.2.0
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204
    technique_name: User Execution
    evidence: Triggering this vulnerability requires the victim to open a malicious GRO file with the `obabel` tool, the `OBConversion` API, or any of the language bindings (Python, Ruby, Java, R, Perl, C#, PHP).
    confidence_band: high
cves:
  - id: CVE-2022-42885
    cvss: 9.8
    epss: 0.00816
references:
  - https://github.com/advisories/GHSA-mw5r-wq2m-397c
  - https://github.com/openbabel/openbabel/commit/fa9a2d9a
---

Open Babel, a widely used C++ library and CLI tool for chemical file format conversions, is affected by a high-severity memory-safety vulnerability, CVE-2022-42885. Discovered in the GRO residue parser, this flaw allows an uninitialized pointer dereference when processing a specially crafted GRO input file. The vulnerability affects all versions up to and including 3.1.1 and was publicly disclosed with a patch in version 3.2.0 on May 26, 2026. Reported by Cisco TALOS, this issue impacts systems where Open Babel's `obabel` tool, `OBConversion` API, or its various language bindings (Python, Ruby, Java, R, Perl, C#, PHP) are used to parse untrusted GRO files. Exploitation can lead to application crashes or potentially arbitrary code execution, posing a significant risk to data processing workflows in chemistry and related scientific fields.

## Attack Chain

1. An attacker crafts a malicious GRO file specifically designed with a malformed residue record to exploit CVE-2022-42885.
2. The attacker delivers this malicious GRO file to a target system, potentially via social engineering tactics such as email attachment or by embedding it within a seemingly legitimate data set.
3. A user or an automated process on the target system opens or attempts to parse the malicious GRO file using the `obabel` CLI tool, an application leveraging Open Babel's `OBConversion` API, or one of its language bindings (e.g., Python, Java).
4. During the parsing of the malformed record, Open Babel's GRO reader attempts to access a residue pointer that has not been properly initialized.
5. This uninitialized pointer dereference leads to a memory access violation within the process.
6. The memory access violation results in the application crashing (denial of service) or, in a more severe scenario, allows the attacker to achieve arbitrary code execution on the host system.

## Impact

This vulnerability impacts systems that utilize Open Babel, particularly those that process GRO chemical file format data from untrusted sources. Since Open Babel is commonly shipped by Linux distributions and embedded in scientific services, a broad range of research institutions, academic organizations, and industrial entities could be affected. Successful exploitation via CVE-2022-42885 leads to immediate application termination, causing denial of service for any service or tool relying on Open Babel's GRO parsing. More critically, skilled attackers could potentially leverage this memory corruption to achieve arbitrary code execution on the compromised system, allowing for data exfiltration, further system compromise, or the deployment of additional malicious payloads.

## Recommendation

- Immediately update all installations of Open Babel to version 3.2.0 or newer to patch CVE-2022-42885.
- Implement strict input validation and sandboxing for applications that process untrusted or user-supplied GRO files using Open Babel.
- Educate users on the risks of opening or processing untrusted files, consistent with the initial access vector that requires a victim to open a malicious GRO file.
