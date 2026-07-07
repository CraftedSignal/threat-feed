---
title: Open Babel Has Uninitialized Pointer Dereference in MSI Atom Parser
slug: 2026-07-open-babel-msi-parser-vuln
description: A memory-safety vulnerability (CVE-2022-44451) in Open Babel's MSI parser allows for an uninitialized pointer dereference when processing a specially crafted MSI input file, affecting versions prior to 3.2.0 and potentially leading to application instability or denial of service when a victim opens a malicious file.
date: "2026-07-03T12:51:24Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:openbabel:open_babel:3.1.1:*:*:*:*:*:*:*
tags:
  - chemistry
  - vulnerability
  - memory-safety
  - open-babel
  - cve
vendors:
  - Open Babel
products:
  - Open Babel (< 3.2.0)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Triggering this vulnerability requires the victim to open a malicious MSI file with the `obabel` tool, the `OBConversion` API, or any of the language bindings
    confidence_band: high
cves:
  - id: CVE-2022-44451
    cvss: 9.8
    epss: 0.00816
references:
  - https://github.com/advisories/GHSA-jr2x-6qf6-q5mc
  - https://github.com/openbabel/openbabel/commit/fa9a2d9a
---

A memory-safety vulnerability, identified as CVE-2022-44451, has been discovered in Open Babel, a widely used C++ library and command-line interface for chemistry file format manipulation. Reported by Cisco TALOS, this flaw exists within Open Babel's MSI atom parser, leading to an uninitialized pointer dereference when processing a specially crafted input file. This vulnerability affects all Open Babel versions up to and including 3.1.1. Attackers could exploit this by convincing a victim to open a malicious MSI file using the `obabel` CLI tool, the `OBConversion` API, or any of its language bindings (Python, Ruby, Java, R, Perl, C#, PHP). This could lead to application instability, crashes, or denial of service on systems that parse untrusted chemical file formats, impacting scientific computing environments and services embedding the library.

## Attack Chain

1.  An attacker crafts a malicious MSI (Molecular Structure Input) file specifically designed to trigger the uninitialized pointer dereference vulnerability (CVE-2022-44451) within Open Babel's parser.
2.  The attacker delivers this malicious MSI file to a target system or user, potentially through phishing emails, malicious websites, or embedding it within a seemingly legitimate data set.
3.  The victim opens or attempts to process the malicious MSI file using the `obabel` command-line tool, an application leveraging the `OBConversion` API, or any of Open Babel's language bindings (e.g., Python, Ruby).
4.  Open Babel's internal MSI parser begins to process the malformed record within the crafted input file.
5.  During atom handling, the parser attempts to dereference an atom pointer that has not been properly initialized, triggering the memory-safety flaw.
6.  This uninitialized pointer dereference causes the Open Babel application or the service embedding it to crash or become unstable.
7.  The final objective is application denial of service or potential arbitrary code execution, impacting the availability and integrity of the affected system.

## Impact

This vulnerability primarily results in application instability or denial of service, as the affected Open Babel process crashes when attempting to parse a malicious MSI file. Given Open Babel's role as a core library and CLI tool shipped by various Linux distributions and embedded in services that process chemical file formats, a successful attack could disrupt scientific computing workflows, research data processing, or any service relying on Open Babel for untrusted input parsing. While no specific victim counts are available, the broad usage of Open Babel implies a significant potential attack surface across academic, research, and industrial sectors utilizing computational chemistry.

## Recommendation

*   Immediately update Open Babel installations to version 3.2.0 or newer to mitigate CVE-2022-44451, as indicated by the `Patched version` details.
*   Implement robust input validation and sanitization for all MSI files processed by applications leveraging Open Babel, especially when dealing with untrusted sources, to prevent malformed records from reaching the vulnerable parser.
*   Monitor for unexpected crashes or abnormal termination of the `obabel` CLI tool or any applications using the `OBConversion` API when processing MSI files, as this could indicate an attempted exploitation of CVE-2022-44451.
