---
title: Stack-Based Out-of-Bounds Write in Ghidra Decompiler
slug: 2026-09-ghidra-oob-write
description: Ghidra versions 12.1.4 and earlier contain a stack-based out-of-bounds write vulnerability in the leftshift128 function that could allow arbitrary code execution when processing malicious binaries.
date: "2026-09-26T02:55:34Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:nsa:ghidra:*:*:*:*:*:*:*:*
tags:
  - cve-2026-100504
  - memory-corruption
  - software-vulnerability
vendors:
  - National Security Agency
products:
  - Ghidra (<= 12.1.4)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Attackers can craft malicious binaries with specific instruction sequences that trigger the overflow when decompiled, corrupting memory and potentially achieving code execution.
    confidence_band: high
cves:
  - id: CVE-2026-100504
    cvss: 7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100504
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade Ghidra to a version greater than 12.1.4
      owner: IT Operations
      addresses: CVE-2026-100504
      evidence: Source identifies Ghidra versions through 12.1.4 as affected
---

Ghidra versions through 12.1.4 contain a stack-based out-of-bounds write vulnerability located in the decompiler's leftshift128 function. This vulnerability is triggered when the decompiler processes p-code containing negative shift amounts. An attacker can exploit this by providing a specially crafted binary containing specific instruction sequences. When a user opens or performs analysis on this malicious binary within Ghidra, the decompiler's memory becomes corrupted during the calculation process. This memory corruption can lead to the execution of arbitrary code with the privileges of the user running the Ghidra application. This is particularly relevant for security researchers and reverse engineers who frequently analyze untrusted binaries.

## Impact

The vulnerability poses a significant risk to the security research community and software analysts who use Ghidra for reverse engineering tasks. If exploited, an attacker could gain control over the analyst's machine, potentially leading to the theft of sensitive project data, intellectual property, or further lateral movement within an organization's network.

## Recommendation

Prioritized, concrete actions for security teams:
- Identify and inventory all instances of Ghidra 12.1.4 or earlier within the development and research environments.
- Upgrade all instances of Ghidra to the latest patched version available from the official National Security Agency repository.
- Implement a policy to sandbox reverse engineering tools, including Ghidra, to minimize the impact of potential arbitrary code execution vulnerabilities.
- Alert users who frequently analyze third-party or untrusted binaries to be cautious when importing unknown files into the Ghidra environment until patches are applied.
