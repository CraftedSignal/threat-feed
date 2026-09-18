---
title: WeaselBiscuit Stealer Distributed via Malicious npm Packages
slug: 2026-09-weaselbiscuit-stealer
description: WeaselBiscuit is a lightweight JavaScript stealer discovered in 13 npm packages that harvests sensitive browser extension storage and performs host profiling across Windows, macOS, and Linux.
date: "2026-09-18T11:28:24Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - npm
  - supply-chain
  - infostealer
  - javascript
  - malware
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195.002
    technique_name: 'Supply Chain Compromise: Compromise Software Dependencies'
    evidence: Cybersecurity researchers have discovered a cluster of 13 npm packages that have been found to deliver a previously undocumented JavaScript stealer codenamed WeaselBiscuit.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: 'Command and Scripting Interpreter: JavaScript'
    evidence: Instead, it's triggered via an npm import, which causes the loader ("loader.js") to pull the main malware from an Npoint dead drop and execute it directly in memory.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: It uploads every readable, nonempty file under the extension's Local Extension Settings directory — a raw LevelDB key/value store — wholesale.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1056.001
    technique_name: 'Input Capture: Keylogging'
    evidence: Based on operator commands received from the C2 server... it can also log clipboard contents and keystrokes on Windows machines.
    confidence_band: high
iocs:
  - type: ip
    value: 103.170.217.184
ioc_counts:
  ip: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Block IP 103.170.217.184 on perimeter firewalls.
      owner: SOC
      due: 24h
      evidence: Source explicitly names this as the C2 infrastructure.
  hunt_leads:
    - lead: Audit installed node_modules for the identified @biz44 prefix or specific package names.
      technique_id: T1195.002
      data_needed:
        - File system inventory
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Package names provided in the source.
  mitigation_plan:
    - priority: immediate
      action: Remove malicious npm packages from local project dependencies.
      owner: IT Operations
      addresses: WeaselBiscuit infection
      evidence: Source identifies 13 specific packages as malicious.
---

WeaselBiscuit is a newly identified, stripped-down JavaScript-based information stealer delivered via 13 malicious npm packages. Identified in September 2026, the malware exhibits functional overlaps with DPRK-linked strains BeaverTail and OtterCookie but is significantly more lightweight, omitting features like persistence and cryptocurrency wallet-draining code. The stealer is triggered upon the import of the malicious npm package, which executes a loader script that fetches the primary payload from a dead-drop hosted on Npoint.io. Once active in memory, it profiles the compromised host and harvests Chrome extension storage, specifically targeting the raw LevelDB files within the Local Extension Settings directory. On Windows systems, the malware gains additional capabilities, including clipboard logging and keystroke capture. While operational similarities to Contagious Interview campaign tooling exist, researchers currently lack definitive attribution evidence.

## Attack Chain

1. Attacker publishes 13 malicious npm packages (e.g., @biz44/id10-client, process-mite) to the npm registry.
2. Victim executes 'npm install' or 'npm import' on the malicious package within a development environment.
3. The 'loader.js' script within the package executes, reaching out to Npoint.io to retrieve the primary malware payload.
4. The payload executes in memory and resolves C2 configuration from a second Npoint URL.
5. The malware profiles the host OS and environment, reporting back to the C2 server (103.170.217.184:8787).
6. The malware iterates through the browser's Local Extension Settings directory to exfiltrate LevelDB key-value stores.
7. On Windows, the agent initiates secondary functions to log clipboard contents and keystrokes.
8. Stolen data is exfiltrated to the C2 infrastructure.

## Impact

The primary impact is the unauthorized exfiltration of sensitive data stored within browser extension local settings, which may include authentication tokens, session data, or sensitive state information for crypto-wallets and other extensions. The malware's ability to log keystrokes and clipboard data on Windows further escalates the risk to credentials and sensitive text input, potentially leading to identity theft or unauthorized account access.

## Recommendation

Prioritize monitoring for the execution of npm install or import operations within developer environments. Block traffic to identified C2 infrastructure and perform threat hunting for the listed npm package names.

* Deploy detection for npm installation of unauthorized or high-risk packages in CI/CD pipelines.
* Block outbound connections to the C2 IP 103.170.217.184 at the network perimeter.
* Audit developer workstations for the presence of the 13 identified malicious npm packages.
* Enable process monitoring to identify unauthorized npm or node.js network activity originating from developer shells.
