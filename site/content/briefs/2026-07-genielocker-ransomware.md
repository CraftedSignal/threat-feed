---
title: Toy Ghouls Deploying Custom GenieLocker Ransomware
slug: 2026-07-genielocker-ransomware
description: The Toy Ghouls threat actor is deploying a custom ransomware family called GenieLocker against manufacturing organizations, utilizing compromised VPN credentials and legitimate system tools for lateral movement and encryption.
date: "2026-07-30T08:12:07Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Toy Ghouls
tags:
  - ransomware
  - extortion
  - manufacturing
  - toy-ghouls
vendors:
  - Microsoft
  - VMware
products:
  - Windows
  - Linux
  - ESXi
  - OpenVPN
  - KeePassXC
  - PsExec
  - PAExec
affected_os:
  - Windows
  - Linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1133
    technique_name: External Remote Services
    evidence: The attackers first entered the environment through an OpenVPN connection originating from an external partner's network.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
    evidence: They employed SoftPerfect Network Scanner for discovery and used Mimikatz to dump credentials.
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
    evidence: The widespread deployment of the encryption Trojan was conducted with the legitimate utilities PsExec and PAExec.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1486
    technique_name: Data Encrypted for Impact
    evidence: On the compromised Linux and ESXi servers, they stopped active virtual machines and encrypted their disks using the ELF version of GenieLocker.
    confidence_band: high
references:
  - https://securelist.com/genielocker-ransomware-for-windows-linux-and-esxi/120843/
iocs:
  - type: hash_md5
    value: 5d62c1349b8981c396c9a23f4f8f053c
ioc_counts:
  hash_md5: 1
rules:
  - title: Detect GenieLocker Ransomware Execution
    description: Detects potential GenieLocker ransomware execution by looking for specific anti-debugging API usage and unexpected process behavior.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1486
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

The Toy Ghouls threat group, also known as Bearlyfy or Labubu, has been observed since March 2026 utilizing a new custom ransomware family identified as GenieLocker. This group primarily targets the manufacturing sector, particularly in the Russian Federation. Previously reliant on established third-party ransomware strains such as LockBit and Babuk, Toy Ghouls has transitioned to their own tooling to reduce external dependencies. GenieLocker is distributed in both PE (Windows) and ELF (Linux/ESXi) variants. The ransomware features anti-debugging, environment-specific secret key requirements for execution, and relies on the libsodium library for encryption. Notably, the group does not utilize a data-leak site or double-extortion tactics, relying instead on manual delivery of ransom demands during the impact phase.

## Attack Chain

1. Initial Access: Attackers gain entry via an OpenVPN connection to an external partner's network using compromised but valid credentials.
2. Discovery: Attackers deploy SoftPerfect Network Scanner to identify internal network resources and assets.
3. Credential Access: Attackers utilize Mimikatz to dump credentials from memory and access KeePassXC password manager databases on compromised hosts.
4. Lateral Movement: Attackers move laterally across the environment using RDP for Windows targets and SSH for Linux servers.
5. Command and Control: Attackers establish a reverse SSH tunnel to facilitate communication with their infrastructure.
6. Payload Deployment: Attackers use legitimate utilities, specifically PsExec and PAExec, to distribute the GenieLocker ransomware binaries across the target environment.
7. Impact: On Windows systems, GenieLocker encrypts files; on Linux/ESXi servers, it terminates active virtual machines and encrypts the underlying disk images to complete the impact phase.

## Impact

Attacks attributed to Toy Ghouls using GenieLocker have primarily affected the manufacturing sector. The ransomware causes significant operational disruption by encrypting file systems and virtual machine disk images. Forensic analysis confirms that the actors do not exfiltrate data, focusing exclusively on operational sabotage and extortion.

## Recommendation

* Deploy the provided Sigma rules to monitor for the execution of unauthorized ransomware binaries and anomalous use of credential harvesting tools like Mimikatz.
* Restrict and monitor the use of PsExec and PAExec within the environment; implement strict allowlisting for these binaries to prevent unauthorized remote execution.
* Enforce multi-factor authentication (MFA) for all VPN and remote access entry points, specifically targeting the external partner networks identified in the intrusion.
* Monitor for the presence of the known GenieLocker hash (5d62c1349b8981c396c9a23f4f8f053c) using Endpoint Detection and Response (EDR) telemetry.
* Audit and restrict access to KeePassXC databases and sensitive credential stores on high-value systems.
