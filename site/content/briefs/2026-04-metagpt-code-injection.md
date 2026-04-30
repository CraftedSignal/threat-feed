---
title: MetaGPT Code Injection Vulnerability (CVE-2026-5970)
slug: 2026-04-metagpt-code-injection
description: A code injection vulnerability, CVE-2026-5970, exists in FoundationAgents MetaGPT up to version 0.8.1, allowing remote attackers to execute arbitrary code via manipulation of the `check_solution` function in the HumanEvalBenchmark/MBPPBenchmark component.
date: "2026-04-09T18:17:04Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - code-injection
  - metagpt
  - cve-2026-5970
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server-Side Code Injection
cves:
  - id: CVE-2026-5970
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5970
  - https://github.com/FoundationAgents/MetaGPT/
  - https://github.com/FoundationAgents/MetaGPT/issues/1942
  - https://github.com/FoundationAgents/MetaGPT/pull/1988
  - https://vuldb.com/vuln/356524
rules:
  - title: Detect MetaGPT Suspicious Process Creation
    description: Detects suspicious process creation potentially related to MetaGPT exploitation.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1505
    data_sources:
      - process_creation
      - windows
  - title: Detect MetaGPT Code Injection Attempt via Network
    description: Detects possible MetaGPT code injection attempts via network communication by looking for suspicious patterns in network data.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1505
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

CVE-2026-5970 is a critical vulnerability affecting FoundationAgents MetaGPT, a framework for multi-agent systems, up to version 0.8.1. The vulnerability resides within the `check_solution` function of the `HumanEvalBenchmark/MBPPBenchmark` component. This flaw enables a remote attacker to inject and execute arbitrary code by manipulating input parameters. The vulnerability has been publicly disclosed and exploits are readily available. The maintainers of the MetaGPT project were notified via pull request but have not yet addressed the issue, increasing the risk to users of affected versions. Successful exploitation could lead to complete system compromise.

## Attack Chain

1.  The attacker identifies a vulnerable MetaGPT instance running a version <= 0.8.1.
2.  The attacker crafts a malicious input designed to exploit the `check_solution` function within the `HumanEvalBenchmark/MBPPBenchmark` component.
3.  The attacker sends the crafted input to the MetaGPT instance, potentially via a network request or other remote interface.
4.  The `check_solution` function processes the malicious input without proper sanitization.
5.  The lack of input sanitization allows the attacker to inject arbitrary code.
6.  The injected code is then executed within the context of the MetaGPT application.
7.  Depending on the privileges of the MetaGPT process, the attacker can gain control of the system or access sensitive data.
8.  The attacker may use this initial access to pivot to other systems within the network, install malware, or exfiltrate data.

## Impact

Successful exploitation of CVE-2026-5970 allows remote attackers to execute arbitrary code on systems running vulnerable versions of FoundationAgents MetaGPT. This can lead to complete system compromise, data breaches, and further malicious activities within the compromised environment. Given the nature of MetaGPT, this could potentially affect development environments, CI/CD pipelines, or even production systems where the framework is utilized, leading to significant financial and reputational damage.

## Recommendation

*   Upgrade to a patched version of MetaGPT as soon as one becomes available.
*   Monitor network traffic for suspicious activity targeting MetaGPT instances, using network connection logs.
*   Implement input validation and sanitization measures within the `check_solution` function (if possible as a temporary mitigation) to prevent code injection.
*   Deploy the Sigma rule below to detect attempts to exploit this vulnerability based on suspicious process creation related to MetaGPT.
*   Review and restrict network access to MetaGPT instances to minimize the attack surface.
