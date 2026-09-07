---
title: Rogue ScreenConnect Clients Distribute Four-Stage VBScript Malware
slug: 2026-09-rogue-screenconnect-worm
description: Threat actors are using compromised ConnectWise ScreenConnect instances to propagate a worm-like, four-stage VBScript infection chain that enables backdooring, UAC bypass, and cryptojacking on connected hosts.
date: "2026-09-07T12:56:11Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - worm
  - social-engineering
  - remote-access
  - malware
vendors:
  - ConnectWise
products:
  - ScreenConnect Remote Access
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566.002
    technique_name: Spearphishing Link
    evidence: three unrelated incidents have been found to use diverse initial access methods, namely a Quick Assist tech-support scam, a phishing-delivered MSI installer, and a fake Geek Squad refund form lure
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.005
    technique_name: Visual Basic
    evidence: observed the clients repeatedly spawning wscript.exe to execute VBScripts
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547.001
    technique_name: Registry Run Keys / Startup Folder
    evidence: The incidents share additional indicators, including a WindowsServiceHost User Run Key pointing to WindowsServiceHost.vbs
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
    evidence: 1.vbs, which profiles the host, checks system resources (e.g., if RAM is over 5 GB), verifies if ScreenConnect is installed, enumerates security products
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1219
    technique_name: Remote Access Software
    evidence: worm-like activity that abuses ConnectWise ScreenConnect to distribute a malicious Visual Basic Script
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1496
    technique_name: Resource Hijacking
    evidence: includes payloads to disable Microsoft Defender reporting, turn off Windows memory integrity, and runs an XMRig cryptocurrency miner.
    confidence_band: high
iocs:
  - type: ip
    value: 45.13.237.190
  - type: domain
    value: tele-sync.opik.net
  - type: ip
    value: 131.123.40.98
  - type: domain
    value: borertors92.anondns.net
ioc_counts:
  domain: 2
  ip: 2
rules:
  - title: Detect Suspicious VBScript Execution from ScreenConnect
    description: Detects wscript.exe or cscript.exe spawning from ScreenConnect client processes, a key indicator of the four-stage VBScript chain.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.005
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Disable TransferFiles and TransferFilesInSession permissions in ConnectWise roles
      owner: IT Operations
      due: 24h
      evidence: ConnectWise advisory recommendations
    - action: Block identified C2 IP addresses and domains
      owner: SOC
      due: 4h
      evidence: Source-provided IOCs
  hunt_leads:
    - lead: Check Registry for WindowsServiceHost Run key
      technique_id: T1547.001
      data_needed:
        - Registry modification logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Incidents share additional indicators including a WindowsServiceHost User Run Key
  mitigation_plan:
    - priority: immediate
      action: Re-image infected hosts
      owner: IT Operations
      addresses: Known-compromised systems
      evidence: Huntress SOC recommendation
---

In August 2026, researchers observed a worm-like campaign abusing ConnectWise ScreenConnect to deploy malicious VBScript chains. Attackers achieve initial access through various social engineering tactics, including tech-support scams using Quick Assist, phishing-delivered MSI installers, and fake refund forms. Once a rogue ScreenConnect client is installed, it repeatedly spawns 'wscript.exe' to execute a sequence of four VBScript files (1.vbs through 4.vbs). This chain profiles the host, enumerates security software (e.g., CrowdStrike, SentinelOne, Sophos), and downloads modular payloads based on system state variables. The malware exhibits worm-like propagation by infecting host machines that connect to an already compromised ScreenConnect client. Depending on the environment, the payload can result in user-level backdoors, UAC bypass for privilege escalation, or the deployment of XMRig cryptocurrency miners. ConnectWise has acknowledged an issue with file transfer behavior in ScreenConnect remote access sessions that facilitates this activity.

## Attack Chain

1. Initial access is established via social engineering (Quick Assist scam, phishing MSI, or fake refund lures) to deploy a rogue ScreenConnect remote access client.
2. The rogue ScreenConnect client triggers the execution of '1.vbs' using 'wscript.exe', which profiles host resources, enumerates installed security products, and writes a state variable to '%TEMP%\value.txt'.
3. '2.vbs' is executed, which checks the state variable and downloads an initial configuration file ('map.txt') from a remote source.
4. '3.vbs' downloads a secondary payload ('out.enc') based on the state variable defined in the first stage.
5. '4.vbs' launches 'runner.ps1' to decrypt 'out.enc', writing the result to '%APPDATA%\Microsoft\Windows\Templates\Classic\sys_cache.zip'.
6. The chain executes a final PowerShell script, 'PyTorchFix.ps1', to finalize the installation of backdoors, privilege escalation tools, or cryptominers.
7. The malware achieves persistence by creating a 'WindowsServiceHost' User Run key pointing to 'WindowsServiceHost.vbs'.
8. The infection propagates as the compromised client records 'ConnectionID' identifiers, infecting subsequent hosts that initiate new ScreenConnect sessions.

## Impact

Impacted organizations face the risk of persistent remote access backdoors, privilege escalation, and unauthorized cryptocurrency mining. Multiple incidents have been identified involving diverse social engineering lures. If successful, the attack results in total system compromise, potential data exfiltration, and lateral movement across remote support infrastructure.

## Recommendation

1. Disable the 'TransferFiles' and 'TransferFilesInSession' permissions within all ConnectWise ScreenConnect role definitions to mitigate the file transfer vector.
2. Implement endpoint detection rules to monitor for 'wscript.exe' or 'cscript.exe' spawning from 'ScreenConnect.Client.exe' or related processes in the temporary directory.
3. Hunt for 'WindowsServiceHost' Run key modifications and associated 'WindowsServiceHost.vbs' files in user AppData directories.
4. Block communication to the identified C2 infrastructure (e.g., 45.13.237.190, 131.123.40.98, tele-sync.opik.net) at the network perimeter.
5. Given the worm-like persistence and potential for deep-system compromise, re-image infected hosts from known-good media.
