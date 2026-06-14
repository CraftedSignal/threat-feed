---
title: Atomic Arch Campaign Leverages Orphaned AUR Packages for Linux Payload Deployment
slug: 2026-06-atomic-arch-npm-campaign
description: The Atomic Arch campaign compromises orphaned Arch User Repository (AUR) packages, modifying their PKGBUILDs to install malicious npm/Bun dependencies like 'atomic-lockfile,' which deploy a Linux payload with credential harvesting, eBPF-based stealth, anti-debugging, and data exfiltration capabilities, impacting approximately 1,500 packages.
date: "2026-06-14T09:00:24Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - supply-chain-attack
  - npm
  - bun
  - linux
  - malware
  - credential-harvesting
  - eBPF
  - rootkit
  - data-exfiltration
vendors:
  - Arch Linux
products:
  - Arch User Repository
  - npm
  - Bun
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195
    technique_name: Supply Chain Compromise
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195
    technique_name: Supply Chain Compromise
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546
    technique_name: Event Triggered Execution
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1564
    technique_name: Hide Artifacts
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1564
    technique_name: Hide Artifacts
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1622
    technique_name: Debugger Evasion
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
references:
  - https://www.sonatype.com/blog/atomic-arch-npm-campaign-adds-malicious-dependency
iocs:
  - type: package_name
    value: atomic-lockfile
  - type: package_name
    value: js-digest
  - type: package_name
    value: lockfile-js
  - type: command
    value: npm install atomic-lockfile minimist chalk
  - type: filename
    value: scales.bpf.c
  - type: url_path
    value: /upload
ioc_counts:
  command: 1
  filename: 1
  package_name: 3
  url_path: 1
rules:
  - title: Detect Atomic Arch Malicious npm/Bun Package Installation
    description: Detects the installation of known malicious npm or Bun packages associated with the Atomic Arch campaign, specifically looking for `npm install` or `bun install` commands followed by the malicious package names 'atomic-lockfile', 'js-digest', or 'lockfile-js'.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.004
      - T1195.003
    data_sources:
      - process_creation
      - linux
  - title: Detect Suspicious Executable Launched by Package Manager
    description: Detects the execution of non-standard binaries from ephemeral locations (like /tmp or /var/tmp) or within package manager directories (node_modules) that are child processes of 'npm' or 'bun'. This indicates potential execution of a malicious payload from a preinstall script.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1059.004
      - T1546.007
    data_sources:
      - process_creation
      - linux
  - title: Detect Potential Exfiltration via HTTP POST /upload
    description: Detects outbound network connections where the HTTP request method is POST and the request path ends with '/upload', which is indicative of the Atomic Arch payload's data exfiltration mechanism.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1041
      - T1567.002
    data_sources:
      - network_connection
      - linux
rules_count: 3
---

Sonatype researchers uncovered the Atomic Arch campaign, which began on June 11, 2026, targeting orphaned packages within the Arch User Repository (AUR). Threat actors are exploiting the AUR's stewardship process by adopting abandoned projects and subsequently modifying their PKGBUILD instructions. These modifications introduce a post-install script designed to install malicious npm packages, such as `atomic-lockfile`, `js-digest`, and `lockfile-js`. A second wave observed on June 12, 2026, also leveraged Bun-based installation paths. The installation of these malicious dependencies triggers the deployment of a sophisticated native Linux executable. This payload is engineered for credential harvesting (targeting GitHub, SSH, Vault, browser data, chat applications), employs eBPF for deep system stealth and privilege escalation, includes anti-debugging features, and possesses HTTP upload functionality for data exfiltration. The campaign is estimated to have affected approximately 1,500 packages, posing a significant supply chain risk where attackers inherit developer trust.

## Attack Chain

1.  **Initial Access & AUR Compromise**: Threat actors identify and gain stewardship of legitimate, but orphaned, packages within the Arch User Repository (AUR).
2.  **PKGBUILD Modification**: The attackers modify the adopted AUR packages' `PKGBUILD` files to include a post-install script that executes package manager commands.
3.  **Malicious Dependency Installation**: When a user installs or updates a compromised AUR package, the modified `PKGBUILD` triggers commands like `npm install atomic-lockfile minimist chalk` (or Bun equivalent) to retrieve and install malicious dependencies.
4.  **Native Payload Execution**: The installed malicious npm/Bun dependency (e.g., `atomic-lockfile`) contains a `package.json` `preinstall` script that executes a bundled native Linux executable.
5.  **Rootkit Deployment & Stealth**: The native Linux executable loads an eBPF program (e.g., `scales.bpf.c`) using `libbpf` APIs (`bpf_object__load`, `bpf_program__attach`, `bpf_map__pin`), enabling advanced process, file, and network hiding (rootkit functionality). It also implements anti-debugging techniques (`PTRACE_ATTACH`, `PTRACE_SEIZE`).
6.  **Credential & Data Harvesting**: The deployed payload actively searches for and collects sensitive information, including GitHub credentials, SSH artifacts, HashiCorp Vault tokens, browser cookie databases, and data from messaging applications like Slack, Discord, Microsoft Teams, and Telegram.
7.  **Data Exfiltration**: The harvested data is compressed and exfiltrated to attacker-controlled infrastructure via HTTP POST requests, specifically targeting endpoints such as `/upload`.

## Impact

The Atomic Arch campaign has a severe impact on developer systems, treating affected hosts as fully compromised. The primary objective is extensive credential and sensitive data harvesting, which could lead to further unauthorized access to developer accounts, source code repositories, cloud infrastructure, and internal systems. The use of eBPF provides deep system stealth, making detection and removal challenging, potentially leading to long-term persistence. With an estimated 1,500 packages affected across multiple waves, this campaign represents a significant supply chain attack that erodes trust in public package repositories, exposing a wide range of organizations using Arch Linux and these packages to sophisticated Linux malware.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect malicious package installations and payload execution.
*   Monitor `process_creation` logs for suspicious `npm` or `bun` commands installing known malicious packages like `atomic-lockfile`, `js-digest`, or `lockfile-js`, as detailed in the rule "Detect Atomic Arch Malicious npm/Bun Package Installation".
*   Monitor `process_creation` logs for unusual executable launches from temporary or `node_modules` directories as a child of `npm` or `bun`, as described in the rule "Detect Suspicious Executable Launched by Package Manager".
*   Enable and monitor `network_connection` logs for outbound HTTP POST requests to suspicious paths like `/upload` from unusual or non-browser processes, as outlined in the rule "Detect Potential Exfiltration via HTTP POST /upload".
*   Review any Arch User Repository (AUR) packages installed within your environment, particularly those adopted around June 2026, for modified `PKGBUILD` files.
