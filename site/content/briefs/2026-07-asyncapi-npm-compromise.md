---
title: AsyncAPI npm Supply Chain Compromise via GitHub Actions
slug: 2026-07-asyncapi-npm-compromise
description: Threat actors compromised AsyncAPI npm packages by exploiting a misconfigured GitHub Actions workflow, stealing a privileged bot token, and injecting obfuscated Miasma malware into multiple packages, which then executed at module-load time to establish persistence and command and control, bypassing standard npm installation mitigations.
date: "2026-07-16T01:50:36Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - supply-chain
  - npm
  - github-actions
  - malware
  - javascript
  - nodejs
  - ci-cd
vendors:
  - AsyncAPI
products:
  - '@asyncapi/generator@3.3.1'
  - '@asyncapi/generator-components@0.7.1'
  - '@asyncapi/generator-helpers@1.1.1'
  - '@asyncapi/specs (6.11.2-alpha.1)'
  - '@asyncapi/specs (6.11.2)'
affected_os:
  - Windows
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195
    technique_name: Supply Chain Compromise
    evidence: Threat actors compromised AsyncAPI packages and weaponized trusted CI/CD workflows to distribute malware through npm.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: The attacker exploited a vulnerable GitHub Actions workflow to steal a privileged bot token.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
    evidence: Heavily obfuscated loaders were inserted into one source file per package.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: '`require()` or `import` triggered the malicious `main()`, which spawned a hidden detached child process.'
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1102
    technique_name: Web Service
    evidence: The child downloaded sync.js from IPFS.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: The Miasma runtime provided encrypted bootstrap, persistence, C2 communication, data return paths, and resilient discovery via Nostr, Ethereum, BitTorrent DHT, libp2p, and IPFS.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: The child downloaded sync.js from IPFS and wrote it to an OS-specific 'NodeJS' masquerade directory.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: The Miasma runtime provided encrypted bootstrap, persistence, C2 communication...
    confidence_band: med
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
    evidence: Six additional capability modules (credential harvest... ) were implemented but disabled in this build.
    confidence_band: med
references:
  - https://www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/
iocs:
  - type: ip
    value: 85.137.53.71
  - type: file_name
    value: sync.js
  - type: email
    value: npm-oidc-no-reply@github.com
ioc_counts:
  email: 1
  file_name: 1
  ip: 1
rules:
  - title: Detect Miasma sync.js Payload Drop
    description: Detects the creation of the Miasma second-stage payload, sync.js, in suspicious 'NodeJS' masquerade directories as described in the AsyncAPI compromise.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1036.003
    data_sources:
      - file_event
      - windows
  - title: Detect Miasma C2 Network Connection
    description: Detects outbound network connections to the identified Miasma command and control (C2) server IP and ports associated with the AsyncAPI npm compromise.
    platform: sigma
    severity: critical
    tactics:
      - command_and_control
    techniques:
      - T1071.001
      - T1102.002
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

Microsoft Threat Intelligence identified a coordinated supply chain compromise affecting the `@asyncapi` npm organization on July 14, 2026. Threat actors exploited a misconfigured GitHub Actions workflow to steal a privileged `asyncapi-bot` Personal Access Token (PAT), enabling them to inject heavily obfuscated malware loaders into five package versions across four AsyncAPI npm packages. These poisoned packages were then published via the project's legitimate CI/CD pipeline, including `@asyncapi/specs` (6.11.2-alpha.1, 6.11.2), `@asyncapi/generator@3.3.1`, `@asyncapi/generator-components@0.7.1`, and `@asyncapi/generator-helpers@1.1.1`. The malicious code, identified as `Miasma` (detected as `Trojan:JS/MiasmStealer.SC` and `Trojan:Script/Supychain.A`), executes at module-load (import/require) time, effectively bypassing the `npm install --ignore-scripts` mitigation. This campaign impacts developer workstations, CI/CD pipelines, container builds, and production services that import the affected versions, establishing persistence and command and control, with capabilities for credential harvesting and propagation.

## Attack Chain

1. An attacker exploits a vulnerable GitHub Actions workflow (`pull_request_target`) in the `asyncapi/generator` repository by submitting a malicious pull request (e.g., PR #2155).
2. The misconfigured workflow executes attacker-controlled code, leading to the theft of a privileged `asyncapi-bot` Personal Access Token (PAT).
3. The attacker uses the stolen PAT to push commits containing heavily obfuscated JavaScript loaders into AsyncAPI package source files (e.g., `index.js`).
4. The project's legitimate CI/CD pipelines, authenticated via GitHub Actions OpenID Connect (OIDC) with the compromised identity `npm-oidc-no-reply@github.com`, publish the poisoned npm packages (e.g., `@asyncapi/specs@6.11.2`).
5. Downstream consumers download and import the compromised AsyncAPI packages; the malicious code executes at `require()` or `import` time, spawning a hidden, detached child process.
6. The child process downloads the `sync.js` second-stage payload (Miasma modular runtime) from an IPFS endpoint.
7. The `sync.js` payload is written to an OS-specific "NodeJS" masquerade directory, establishing persistence and initiating active command and control (C2) communication with `85.137.53.71` on ports `8080`, `8081`, and `8091`.
8. The Miasma runtime establishes resilient C2 communication channels and has capabilities for credential harvesting, encrypted exfiltration, and supply-chain propagation, though some modules were disabled in this observed build.

## Impact

The compromise of AsyncAPI npm packages directly impacts developer workstations, CI/CD pipelines, container builds, and production services that resolved and imported the affected versions. The `Miasma` modular runtime establishes persistent access and active command and control, posing a significant risk for further exploitation, including potential credential harvesting, data exfiltration, and lateral movement within compromised environments. Microsoft Defender Antivirus detects the malicious artifacts as `Trojan:JS/MiasmStealer.SC` and `Trojan:Script/Supychain.A`. If successful, this supply chain attack could lead to widespread code integrity issues, intellectual property theft, and unauthorized access to development infrastructure.

## Recommendation

* Immediately remove all five affected package versions: `@asyncapi/specs@6.11.2-alpha.1`, `@asyncapi/specs@6.11.2`, `@asyncapi/generator@3.3.1`, `@asyncapi/generator-components@0.7.1`, and `@asyncapi/generator-helpers@1.1.1`.
* Purge npm and Yarn caches on all affected systems to ensure no cached malicious packages are re-installed.
* Hunt for the `sync.js` file under "NodeJS" masquerade directories across developer workstations and CI/CD environments using `Detect Miasma sync.js Payload Drop` Sigma rule.
* Block outbound connections to `85.137.53.71` on ports `8080`, `8081`, and `8091` at your network perimeter using `Detect Miasma C2 Network Connection` Sigma rule.
* Rotate all credentials (including GitHub Personal Access Tokens and npm authentication tokens) that were accessible from any environment or service that imported the compromised packages.
* Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect `Miasma` activity.
