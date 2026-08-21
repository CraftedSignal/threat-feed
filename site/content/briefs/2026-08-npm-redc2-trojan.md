---
title: Trojanized npm Packages Distribute RedC2 4.0 Linux Backdoor
slug: 2026-08-npm-redc2-trojan
description: Fourteen trojanized npm packages masquerading as utility libraries deliver the RedC2 4.0 'RedShell' Linux beacon, which features AI-assisted command execution and cross-platform post-exploitation capabilities.
date: "2026-08-21T20:31:50Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - supply-chain
  - npm
  - malware
  - linux
  - c2
  - redc2
affected_os:
  - Linux
  - Windows
  - macOS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195.002
    technique_name: Supply Chain Compromise
    evidence: Cybersecurity researchers have discovered a set of trojanized npm packages that masquerade as working calendar and streak utilities.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: Command and Scripting Interpreter
    evidence: The Linux variant of the beacon, once deployed, provides an interactive shell through /bin/sh.
    confidence_band: high
rules:
  - title: Detect Execution of Binaries from npm Node Modules
    description: Detects cases where a Node.js process spawns a binary located within the node_modules directory, which is a common indicator of a supply chain loader.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Audit environment for existence of identified malicious npm packages
      owner: SOC
      due: 24h
      evidence: Source provides list of 14 trojanized packages.
  hunt_leads:
    - lead: Search for unexpected binary files in node_modules/dist/ directories
      technique_id: T1059.004
      data_needed:
        - File integrity monitoring / EDR file scan logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source identifies binary names like math-core.bin and calc.bin.
---

Fourteen trojanized npm packages have been identified that appear to provide legitimate calendar and streak utility functionality but act as delivery mechanisms for the RedC2 4.0 Linux backdoor. The malicious packages, discovered by researchers, execute a bundled binary named 'RedShell' upon being imported into any application dependency graph. This execution occurs without the requirement of install hook functions or specific exported method calls, significantly increasing the probability of silent infection.

RedC2 4.0 is a sophisticated C2 framework marketed on cybercrime forums by the actor 'MarlboroMan'. It is designed for cross-platform operations, including Windows, Linux, and macOS. The Linux variant provides interactive shell access, credential theft, and network pivoting capabilities. The framework is notable for its integration of 'Red Agent', an LLM-driven component that allows operators to issue post-exploitation commands in natural language, abstracting the complexity of manual command-line sequences.

## Attack Chain

1. Attacker publishes trojanized npm packages (e.g., streak-metrics-math@1.0.0) containing a hidden binary payload under the 'dist/' or 'dist/internal/' directories.
2. Victim environment imports the malicious package, triggering the 'dist/index.mjs' loader file.
3. The loader script identifies the bundled binary (e.g., math-core.bin, calc.bin) and programmatically modifies file permissions to make it executable.
4. The loader launches the 'RedShell' beacon binary as a detached, background process, bypassing common installation-time analysis.
5. The RedShell beacon establishes communication with the attacker's C2 server and transmits host system information in a registration 'check-in' message.
6. The beacon enters a command-processing loop to receive instructions, which are executed via '/bin/sh' on the host.
7. Operators utilize 'Red Agent' (LLM-based) to translate natural-language intent into specific framework commands for lateral movement, data collection, or further payload delivery.
8. Exfiltrated data (SSH keys, browser credentials) is transmitted back to the C2 operator through the established channel.

## Impact

Successful deployment of the RedShell beacon grants an attacker persistent interactive access to the Linux host. The framework facilitates mass credential harvesting, network visualization, and the execution of shellcode or BOFs in-memory. This poses a severe risk to development environments and CI/CD pipelines where npm packages are frequently used, potentially allowing attackers to pivot into internal infrastructure and orchestrate complex, multi-stage intrusions.

## Recommendation

* Deploy detection rules targeting the execution of binaries directly from node_modules directories, as documented in the detection rules below.
* Audit project dependencies for the package names identified in this brief (e.g., streak-metrics-math, kit-map-vim, streak-map-cache, etc.) and remove them if present.
* Implement egress filtering on build servers and developer workstations to block connections to unauthorized external IP addresses or domains identified as C2 infrastructure.
* Use npm lockfiles to pin dependency versions and perform integrity checks to ensure that no unexpected sub-dependencies have been introduced to the application.
* Monitor for unexpected background processes spawned by Node.js or npm-related processes.
