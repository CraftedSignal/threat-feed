---
title: OpenClaw Workspace .env Homebrew Executable Override Vulnerability (CVE-2026-53819)
slug: 2026-07-openclaw-homebrew-override
description: A high-severity vulnerability (CVE-2026-53819) in OpenClaw versions prior to 2026.5.27 allows a malicious `.env` file within a repository to override the Homebrew executable selection during skill installation flows, potentially leading to arbitrary code execution on trusted operator systems running macOS or Linux.
date: "2026-07-03T12:01:45Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:openclaw:openclaw:*:*:*:*:*:node.js:*:*
tags:
  - vulnerability
  - code-execution
  - homebrew
  - supply-chain
  - macos
  - linux
vendors:
  - OpenClaw
products:
  - OpenClaw (< 2026.5.27)
affected_os:
  - macOS
  - Linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: this could run an unintended Homebrew-compatible executable during skill setup
    confidence_band: high
cves:
  - id: CVE-2026-53819
    cvss: 8.8
    epss: 0.00298
references:
  - https://github.com/advisories/GHSA-8wg3-5mcm-fjq8
---

The OpenClaw platform is affected by CVE-2026-53819, a high-severity vulnerability enabling a malicious `.env` file in a repository to manipulate the Homebrew executable selection during skill installation flows. Published by GHSA on July 2, 2026, this flaw permits the OpenClaw install helper to use an attacker-controlled Homebrew-compatible binary instead of the legitimate one. This occurs when a trusted operator opens an affected workspace and initiates a skill installation. The vulnerability, present in OpenClaw versions prior to 2026.5.27, affects macOS and Linux systems and poses a significant risk for arbitrary code execution, bypassing established security controls and potentially compromising the operator's environment.

## Attack Chain

1.  An attacker crafts a malicious repository that includes a `.env` file designed to alter environment variables that influence Homebrew's path resolution.
2.  The attacker socially engineers a trusted OpenClaw operator to clone and open this malicious repository within their development workspace.
3.  The trusted operator initiates a skill install flow within the newly opened, compromised workspace.
4.  During the install process, the OpenClaw install helper parses the malicious `.env` file, causing it to load an incorrect or attacker-controlled path for the Homebrew executable.
5.  Instead of executing the legitimate Homebrew binary, the system invokes an attacker-controlled Homebrew-compatible executable, which was likely bundled within the malicious repository.
6.  The attacker-controlled executable runs with the operator's privileges, achieving arbitrary code execution on the host system.
7.  This execution could lead to system compromise, data exfiltration, or further lateral movement within the network.

## Impact

Successful exploitation of CVE-2026-53819 could allow an attacker to run arbitrary code on a trusted operator's system, leading to full system compromise. The practical impact depends on the specific configuration of the operator's environment and the attacker's payload. If lower-trust input can reach the affected path, it increases the likelihood and severity of compromise. This vulnerability could be leveraged for initial access, privilege escalation, or establishing persistence within targeted development environments, potentially affecting intellectual property or critical infrastructure if operators with elevated access are targeted.

## Recommendation

*   Immediately patch OpenClaw to version `2026.5.27` or newer to remediate CVE-2026-53819.
*   Avoid running skill install flows from untrusted workspaces until all OpenClaw instances are updated to the patched version `2026.5.27`.
*   As a general hardening measure, keep channel and tool allowlists narrow, as noted in the GHSA reference.
*   Disable the affected feature when it is not needed to reduce the attack surface for CVE-2026-53819.
