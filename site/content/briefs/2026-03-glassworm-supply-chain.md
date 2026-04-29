---
title: GlassWorm Supply Chain Attack Using Unicode Encoding and Credential Theft
slug: 2026-03-glassworm-supply-chain
description: The GlassWorm campaign employs Unicode variation selectors to conceal malicious code within supply chain artifacts, subsequently querying a Solana wallet for C2 URLs and exfiltrating sensitive credentials.
date: "2026-03-24T14:30:00Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - supply-chain
  - credential-theft
  - unicode-encoding
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://www.reddit.com/r/blueteamsec/comments/1s1ft8s/techniquebased_detection_for_glassworm_supply/
  - https://github.com/afine-com/glassworm-hunter
rules:
  - title: Unicode Payload Detection
    description: Detects files with high densities of Unicode variation selector characters, indicative of GlassWorm-encoded payloads.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1027
    data_sources:
      - file_event
      - linux|windows|macos
  - title: GlassWorm Decoder Detection
    description: Detects the GlassWorm decoder pattern using codePointAt() with arithmetic and eval() or Function().
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1027
      - T1059.006
    data_sources:
      - process_creation
      - linux|windows|macos
rules_count: 2
---

The GlassWorm campaign, active since October 2025, targets software supply chains through malicious code concealed using Unicode variation selectors. This technique renders the payload virtually invisible in standard editors and code review processes. The attackers rotate extension IDs, npm package names, wallet addresses, and C2 infrastructure across multiple waves. A decoder component extracts the hidden bytes and executes them via `eval()` or `Function()`. The malware queries a Solana wallet to dynamically retrieve C2 URLs and proceeds to steal sensitive information, including `.npmrc`, `.git-credentials`, SSH keys (`id_rsa`, `id_ed25519`), and token environment variables such as `NPM_TOKEN`, `GITHUB_TOKEN`, and `OPEN_VSX_TOKEN`. Wave 5, observed in March, compromised over 150 GitHub repositories, 72 Open VSX extensions, and 4 npm packages. Defenders relying solely on IOC-based detections may struggle to keep pace with the rapid evolution of this threat.

## Attack Chain

1.  Malicious code is injected into a software supply chain component (VS Code extension, npm package, etc.).
2.  The payload is encoded using Unicode variation selectors, rendering it nearly invisible.
3.  The victim installs or incorporates the compromised component into their development environment.
4.  A decoder routine within the payload utilizes `codePointAt()` with arithmetic against `0xFE00/0xE0100` to reconstruct the original bytecode.
5.  The decoded bytecode is executed using `eval()` or `Function()`.
6.  The executed code queries a Solana wallet using RPC methods (`getTransaction`, `getSignaturesForAddress`) to retrieve C2 URLs.
7.  The malware targets files such as `.npmrc`, `.git-credentials`, `id_rsa`, and `id_ed25519` for credential theft.
8.  Stolen credentials and token environment variables (`NPM_TOKEN`, `GITHUB_TOKEN`, `OPEN_VSX_TOKEN`) are exfiltrated to the C2 server.

## Impact

The GlassWorm campaign has successfully compromised over 150 GitHub repositories, 72 Open VSX extensions, and 4 npm packages in Wave 5 alone. Successful attacks can lead to the theft of sensitive credentials, potentially granting attackers unauthorized access to code repositories, package management accounts, and other critical infrastructure. This, in turn, can enable further supply chain attacks or intellectual property theft.

## Recommendation

*   Implement the Unicode payload detection rule to identify suspicious densities of Unicode variation selector clusters in source code (see "Unicode Payload Detection" rule below).
*   Deploy the decoder detection rule to flag code patterns that use `codePointAt()` with specific arithmetic operations followed by `eval()` or `Function()` calls (see "GlassWorm Decoder Detection" rule below).
*   Monitor for network connections originating from non-blockchain applications using Solana RPC methods (`getTransaction`, `getSignaturesForAddress`), as described in the overview, to identify potential C2 activity.
*   Implement access controls and monitoring for sensitive files like `.npmrc`, `.git-credentials`, and SSH keys as described in the overview.
*   Use the `glassworm-hunter` tool linked in the references section to scan VS Code extensions, node_modules, pip site-packages, and git repos.
