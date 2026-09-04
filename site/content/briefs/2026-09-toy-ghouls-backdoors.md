---
title: Toy Ghouls Deploying Custom HiveMQ and Matrix-Based Backdoors
slug: 2026-09-toy-ghouls-backdoors
description: The threat actor Toy Ghouls is using WinRM to deploy custom 'Bird' backdoors that utilize HiveMQ MQTT brokers and the Matrix protocol for C2, featuring machine-bound encrypted configurations.
date: "2026-09-04T12:03:06Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Toy Ghouls
tags:
  - backdoors
  - persistence
  - winrm
  - c2
  - mqtt
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
    evidence: The backdoor can both run within an interactive command-line session and establish persistence as a Windows service.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: In this campaign, the attackers use Windows Remote Management (WinRM) to deliver the backdoors and their configuration files to compromised systems.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: The first version uses the public HiveMQ MQTT broker (broker.hivemq.com) as its C2 server.
    confidence_band: high
references:
  - https://securelist.com/toy-ghouls-new-hivemq-and-element-backdoors/121270/
iocs:
  - type: domain
    value: broker.hivemq.com
ioc_counts:
  domain: 1
rules:
  - title: Detect Toy Ghouls Bird Agent Service Installation
    description: Detects the installation of the HiveMQ or Matrix bird agents as Windows services using specific command-line arguments.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1543.003
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma detection for service installation
      owner: Detection Engineering
      due: 24h
      evidence: Source documents the --install option for persistence.
  hunt_leads:
    - lead: Search for unexpected registry keys in HKLM\Software\synapse\Config\
      technique_id: T1547
      data_needed:
        - Registry event logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Configuration parameters are stored in the registry key HKLM\Software\synapse\Config\SealedConfig
  mitigation_plan:
    - priority: immediate
      action: Tighten WinRM access policies
      owner: IT Operations
      addresses: WinRM delivery vector
      evidence: The attackers use Windows Remote Management (WinRM) to deliver the backdoors.
---

Toy Ghouls (also known as Bearlyfy, Laboo.boo, and Feral Wolf) has pivoted from using publicly available malware builders to deploying custom backdoors designated as 'mqtt-bird-agent' and 'matrix-bird-agent'. Observed in early July 2026, these tools target Russian organizations and leverage legitimate infrastructure for command-and-control. The HiveMQ version uses the public MQTT broker (broker.hivemq.com), while the Element version utilizes the Matrix protocol to facilitate communication. Both versions employ sophisticated configuration management, using the ChaCha20-Poly1305 algorithm keyed against the Windows MachineGuid to bind sensitive C2 parameters to the infected host. The attackers favor living-off-the-land techniques for delivery, specifically utilizing Windows Remote Management (WinRM) to drop and execute these payloads. The group's transition to proprietary backdoors represents a significant increase in operational security and persistence capability.

## Attack Chain

1. The attacker gains initial access and establishes a WinRM session to the target system.
2. The attacker uses Evil-WinRM or WinRM-fs to upload the backdoor executable (e.g., cplsupport.exe or wtass.exe) and an associated config.toml file.
3. The backdoor is executed via command-line, performing a callback to http://ip-api.com to resolve the host's public IP and country.
4. The backdoor reads the configuration file; if unencrypted, it uses the HKLM\Software\Microsoft\Cryptography\MachineGuid to generate a key for ChaCha20-Poly1305 encryption of the config.
5. The backdoor is installed as a Windows service for persistence using the --install or install command-line options.
6. Configuration parameters are stored in either %PROGRAMDATA% (HiveMQ version) or the registry key HKLM\Software\synapse\Config\SealedConfig (Element version).
7. The backdoor initiates C2 communication, connecting to either the HiveMQ broker (broker.hivemq.com) or the attacker-controlled Matrix homeserver for tasking.
8. The final objective involves C2-driven task execution for lateral movement, data exfiltration, or further malware deployment.

## Impact

Successful deployment of these backdoors grants the attackers persistent, interactive access to compromised hosts. The use of machine-bound encryption complicates security analysis and prevents the reuse of stolen configuration files across different environments. Organizations targeted by Toy Ghouls face high risks of sensitive data exfiltration and the subsequent deployment of custom ransomware, such as GenieLocker.

## Recommendation

* Deploy the Sigma rule below to detect unauthorized service installations of the 'Bird' backdoors.
* Monitor for network connections to broker.hivemq.com and traffic patterns associated with the Matrix protocol from non-standard endpoints.
* Restrict WinRM access to only known administrative management hosts and monitor for the usage of tools like Evil-WinRM.
* Baseline Registry modifications to HKLM\Software\synapse\Config\SealedConfig.
