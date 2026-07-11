---
title: Multi-Group Espionage Targets Pakistani Law Enforcement via Weaponized Police Portal
slug: 2026-07-pakistani-police-espionage
description: Suspected China- and India-aligned threat actors conducted sustained cyber espionage campaigns between February 2024 and April 2026, compromising Pakistani law enforcement organizations' web applications, network appliances, and email gateways, including the Balochistan Police's Complaint Management System to deploy malware like PlugX, ShadowPad, Cobalt Strike, Remcos RAT, a Rust stager (cms_plugin.exe), and AsyncRAT.
date: "2026-07-11T18:53:22Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cyber-espionage
  - nation-state
  - malware
  - rat
  - windows
vendors:
  - Fortinet
products:
  - FortiMail
  - Complaint Management System
  - Smart Police Station digitalization initiative web applications
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: By hosting implants in a portal used by both citizens and law enforcement personnel, the threat actor turned a tool built to make policing in Pakistan more accessible and accountable to the public into a malware delivery mechanism.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: A Rust stager that's designed to download an additional payload from '193.42.25[.]65' and execute it.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: A .NET executable that masquerades as '360Safe.exe,' a legitimate binary used by Qihoo 360 Total Security, to reflectively load an assembly implementing an AsyncRAT client.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: A Rust stager that's designed to download an additional payload from '193.42.25[.]65'
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: traffic to the attacker-controlled command-and-control (C2) server ('142.171.183[.]8') extends beyond Pakistani law enforcement to government, academic, telecommunications, and non-governmental entities
    confidence_band: high
references:
  - https://thehackernews.com/2026/07/hackers-weaponize-balochistan-police.html
iocs:
  - type: ip
    value: 142.171.183.8
  - type: ip
    value: 193.42.25.65
  - type: domain
    value: cms.balochistanpolice.gov.pk
  - type: filename
    value: cms_plugin.exe
  - type: filename
    value: 360Safe.exe
ioc_counts:
  domain: 1
  filename: 2
  ip: 2
rules:
  - title: Detect cms_plugin.exe Execution (Rust Stager)
    description: Detects the execution of cms_plugin.exe, a Rust stager implant observed in espionage campaigns against Pakistani law enforcement, which downloads additional payloads.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059
      - T1204.002
    data_sources:
      - process_creation
      - windows
  - title: Detect 360Safe.exe Masquerading for AsyncRAT
    description: Detects the execution of 360Safe.exe when used as a malicious binary to load AsyncRAT, masquerading as a legitimate Qihoo 360 Total Security component. This rule specifically looks for execution outside typical legitimate paths or suspicious parent processes.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1036.003
      - T1059
    data_sources:
      - process_creation
      - windows
  - title: Detect Network Connections to Espionage C2 IPs
    description: Detects outbound network connections to known attacker-controlled command-and-control (C2) servers identified in multi-group espionage campaigns targeting Pakistani law enforcement.
    platform: sigma
    severity: critical
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 3
---

Between February 2024 and April 2026, suspected state-sponsored cyber espionage groups, including China-aligned actors and the India-nexus threat actor Mysterious Elephant (APT-C-08), conducted targeted attacks against various Pakistani law enforcement organizations. The campaigns involved compromising critical infrastructure such as network appliances, web servers hosting sensitive applications, and Fortinet FortiMail email gateways belonging to entities like the Balochistan Police, Khyber Pakhtunkhwa Police, Islamabad Police, and Punjab Safe Cities Authority. Attackers weaponized the compromised Balochistan Police Complaint Management System (CMS), accessible at `cms.balochistanpolice.gov.pk`, by uploading malicious implants disguised as portal updates, such as a Rust stager named `cms_plugin.exe` and a .NET executable `360Safe.exe` which loads AsyncRAT. These implants were designed to deliver further payloads (including PlugX, ShadowPad, Cobalt Strike, and Remcos RAT) and exfiltrate sensitive data including criminal, biometric, hotel, tenant, and personnel records, extending the threat actor's reach to both law enforcement staff and citizens interacting with the portal.

## Attack Chain

1. Threat actors gain initial access to network appliances, web servers (including those hosting the Complaint Management System and Smart Police Station applications), and Fortinet FortiMail appliances within Pakistani law enforcement networks.
2. Attackers weaponize the compromised Complaint Management System (CMS) portal (`cms.balochistanpolice.gov.pk`) by deploying malicious files masquerading as legitimate portal updates.
3. A Rust stager, named `cms_plugin.exe`, is uploaded to the compromised CMS web application.
4. Police staff or citizens, interacting with the CMS, are prompted with a fake "Update Complete! Please refresh the page" message and execute the malicious `cms_plugin.exe`.
5. Upon execution, the `cms_plugin.exe` stager downloads additional payloads from attacker-controlled infrastructure, such as `193.42.25[.]65`.
6. A .NET executable, `360Safe.exe`, masquerading as legitimate security software, is deployed to reflectively load an AsyncRAT client, establishing persistent access and control.
7. Various malware families, including PlugX, ShadowPad, Cobalt Strike, and Remcos RAT, are deployed to victim systems, utilizing C2 servers such as `142.171.183[.]8` for communication.
8. Threat actors perform cyber espionage, collecting and exfiltrating sensitive police and citizen data, including criminal, biometric, hotel registration, and personnel records, for intelligence gathering.

## Impact

These sustained espionage campaigns severely impact the integrity and confidentiality of sensitive national security and citizen data across multiple Pakistani law enforcement agencies. The compromise of web applications managing criminal and biometric records, hotel and tenant registrations, criminal case files, and personnel records exposes vast amounts of personally identifiable information and operational intelligence. The weaponization of public-facing portals like the Complaint Management System transforms them into malware delivery mechanisms, potentially compromising both law enforcement personnel and the citizens they serve. The intelligence gathered by these state-sponsored groups provides significant geopolitical advantages and insights into Pakistan's internal security picture, undermining national security and public trust in digital government services.

## Recommendation

* **Monitor** process creation logs for the execution of suspicious binaries like `cms_plugin.exe` and `360Safe.exe` as identified in the IOCs and rules section.
* **Block** network connections to the identified attacker C2 IP addresses `193.42.25[.]65` and `142.171.183[.]8` at the perimeter firewall and DNS resolvers.
* **Review** web server access logs for `cms.balochistanpolice.gov.pk` and other public-facing applications for unauthorized file uploads or suspicious activity indicative of web shell deployment or compromise.
* **Implement** and **enforce** application whitelisting policies to prevent the execution of unauthorized executables like `cms_plugin.exe` and `360Safe.exe`.
* **Deploy** the Sigma rules in this brief to your SIEM and tune for your environment to detect `cms_plugin.exe` and `360Safe.exe` execution and C2 communications.
* **Patch** all internet-facing Fortinet FortiMail appliances and web applications, including the Complaint Management System, immediately with the latest security updates to address any known vulnerabilities that could have facilitated initial access.
