---
title: TA4922 Deploys PackClient RAT Framework
slug: 2026-08-packclient-ta4922
description: The Chinese-speaking threat actor TA4922 is actively using the modular PackClient C2 framework, delivered via tax-themed spearphishing, to conduct surveillance and deploy follow-on tools like ManageEngine RMM.
date: "2026-08-27T11:39:31Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - TA4922
tags:
  - rat
  - phishing
  - c2-framework
  - espionage
vendors:
  - ManageEngine
products:
  - Remote Monitoring and Management
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: The campaign used a tax-themed lure and impersonated the Shandong Provincial Tax Bureau with compliance language to pressure recipients into action.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The malware uses DLL sideloading to execute Donut Loader and ultimately install PackClient.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: 'Sets registry autorun persistence: reg add HKCU\...\RunOnce /v RuntimeBroker /d "%TEMP%\svchost[.]exe"'
    confidence_band: high
references:
  - https://www.proofpoint.com/us/blog/threat-insight/carry-compromise-ta4922-packs-packclient
iocs:
  - type: domain
    value: gov12366.com
  - type: ip
    value: 64.81.30.99
  - type: ip
    value: 192.252.180.45
ioc_counts:
  domain: 1
  ip: 2
rules:
  - title: Detect PackClient Guard Process Behavior
    description: Detects the PackClient core module spawning a guardian process to maintain persistence via the --guard command line argument.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Block identified C2 IPs and domains at the egress firewall.
      owner: SOC
      due: 24h
      evidence: Source provides confirmed C2 infrastructure.
  hunt_leads:
    - lead: Search for processes spawned with '--guard' argument.
      technique_id: T1547.001
      data_needed:
        - Process creation events
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: PackClient documentation of a guard process.
---

Proofpoint researchers have identified a new, modular command and control (C2) framework dubbed PackClient, currently utilized by the Chinese-speaking threat actor TA4922. The malware is being actively marketed on Telegram and features a sophisticated multi-stage infection chain. Campaigns observed between May and July 2026 targeted organizations in China and India using tax-themed phishing lures that impersonated local tax authorities to pressure victims into executing malicious archives (ZIP/IMG). PackClient is highly modular, supporting data exfiltration, keylogging, and the download of secondary payloads, such as ManageEngine RMM software. The framework employs a unique process tree, including a dedicated "guard" process to ensure the RAT remains active on the victim's host, making it a critical threat to organizations in the targeted regions.

## Attack Chain

1. TA4922 sends spearphishing emails with tax-inspection notices, directing users to download a ZIP archive containing an executable or an IMG disk image.
2. The user executes a payload or mounts the IMG, initiating a DLL sideloading process (e.g., using a legitimate library like nvdahelperremote.dll).
3. A Stage 1 loader is executed, which checks for elevated permissions, decrypts an embedded Stage 2 payload, and writes it to disk (e.g., %TEMP%\svchost.exe).
4. The loader establishes persistence by adding an entry to the HKCU RunOnce registry key.
5. The Stage 2 "PackClientLauncher" module is executed, which contacts a hardcoded C2 server to download the Stage 3 "PackClientCore" module.
6. The core module is reflectively loaded into memory and initialized using a configuration found in the .rdata section or registry.
7. A secondary guard process is spawned with the '--guard' flag to monitor the main process and perform auto-restart if terminated.
8. The attacker deploys follow-on tools, such as ManageEngine RMM, to maintain persistent remote access and exfiltrate data.

## Impact

TA4922 campaigns have targeted government, financial, and enterprise entities in China and India. Successful compromise grants the actor full remote control, including surveillance capabilities, keylogging, and the ability to download arbitrary secondary payloads. This facilitates long-term espionage and unauthorized access to sensitive financial and corporate data.

## Recommendation

* Deploy the provided Sigma rule to detect the unique PackClient process tree and guard process behavior.
* Block the actor-controlled infrastructure domains (gov12366[.]com) and IPs at the organization's perimeter DNS and firewall.
* Monitor for unauthorized execution of ManageEngine RMM binaries in environments where they are not officially managed by IT.
* Implement restrictive policies on mounting IMG files and executing unsigned binaries from the %TEMP% directory.
