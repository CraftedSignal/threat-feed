---
title: Rival Espionage Actors Converge on Pakistani Law Enforcement
slug: 2026-07-rival-espionage-pakistan
description: Suspected China- and India-nexus threat actors conducted separate cyberespionage operations against several Pakistani law enforcement organizations, including Balochistan Police, from February 2024 to April 2026, compromising web applications and network appliances with tools like PlugX, ShadowPad, Cobalt Strike, and Remcos to exfiltrate sensitive criminal and biometric data.
date: "2026-07-09T12:57:07Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cyberespionage
  - nation-state
  - data-exfiltration
  - web-application
  - command-and-control
  - malware
products:
  - web applications
  - Complaint Management System
  - network appliances
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: At Balochistan Police, the compromised assets included servers hosting web applications that manage police and citizen data, such as criminal and biometric records.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1036
    technique_name: Masquerading
    evidence: A suspected China-nexus threat actor also compromised one of these web applications, deploying custom implants masquerading as a portal update.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: SentinelLABS has been tracking sustained cyberespionage activity against several Pakistani law enforcement organizations, taking place from February 2024 to April 2026.
    confidence_band: med
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Our analysis of C2 netflow data revealed that suspected China- and India-nexus threat actors operating PlugX, ShadowPad, Cobalt Strike, and Remcos infrastructure have converged on this victim class.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: Our analysis of C2 netflow data revealed that suspected China- and India-nexus threat actors operating PlugX, ShadowPad, Cobalt Strike, and Remcos infrastructure have converged on this victim class.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: At Balochistan Police, the compromised assets included servers hosting web applications that manage police and citizen data, such as criminal and biometric records.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
    evidence: Our analysis of C2 netflow data revealed that suspected China- and India-nexus threat actors operating PlugX, ShadowPad, Cobalt Strike, and Remcos infrastructure have converged on this victim class.
    confidence_band: high
references:
  - https://www.sentinelone.com/labs/one-target-china-india-espionage-converge-on-pakistani-law-enforcement/
iocs:
  - type: ip
    value: 172.111.233.36
  - type: ip
    value: 172.111.233.96
  - type: ip
    value: 172.111.233.12
  - type: ip
    value: 172.111.233.105
  - type: ip
    value: 172.111.233.26
  - type: ip
    value: 172.94.9.49
  - type: ip
    value: 172.94.9.43
  - type: ip
    value: 172.94.9.19
  - type: ip
    value: 45.74.6.17
  - type: ip
    value: 45.125.32.218
  - type: ip
    value: 142.171.183.8
  - type: ip
    value: 193.42.25.65
  - type: ip
    value: 89.31.121.220
ioc_counts:
  ip: 13
rules:
  - title: Detect Outbound Network Connections to Known Espionage C2 IPs
    description: Detects outbound network connections from internal systems to known Command and Control (C2) IP addresses used by suspected China- and India-nexus espionage actors for PlugX, ShadowPad, Cobalt Strike, and Remcos.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 1
---

Suspected China- and India-nexus threat actors conducted separate cyberespionage operations targeting several Pakistani law enforcement organizations, primarily Balochistan Police, from February 2024 to April 2026. These distinct groups compromised web applications, such as the Complaint Management System, and network appliances. China-nexus actors deployed custom implants, masquerading as portal updates, to weaponize these applications against both police staff and citizens. The attackers utilized post-exploitation tools like PlugX, ShadowPad, Cobalt Strike, and Remcos for command and control and data exfiltration, communicating with various identified C2 IP addresses. The targeting of law enforcement bodies provides insights into Pakistan's internal security, driven by China's concern for its nationals' safety and India's adversarial relationship with Pakistan over regional insurgencies.

## Attack Chain

1. **Initial Access**: Threat actors gain access to externally facing web applications (e.g., Complaint Management System) and network appliances belonging to Pakistani law enforcement.
2. **Deployment**: China-nexus actors deployed custom implants masquerading as legitimate portal updates within compromised web applications.
3. **Execution**: Malicious implants are executed on the compromised servers or workstations, establishing an initial foothold within the victim environment.
4. **Command and Control**: Post-exploitation tools like PlugX, ShadowPad, Cobalt Strike, and Remcos communicate with external command and control (C2) servers over network connections (e.g., 172.111.233.36, 45.125.32.218).
5. **Collection**: Threat actors accessed and collected sensitive data from compromised servers, including criminal records, biometric information, hotel and tenant registrations, and personnel data.
6. **Exfiltration**: Collected sensitive data is transferred from the compromised networks to attacker-controlled C2 infrastructure via established communication channels.
7. **Persistence**: Implants and other malicious components are maintained on compromised systems, ensuring sustained access for long-term espionage objectives.

## Impact

The intrusions resulted in the compromise of servers hosting critical web applications managing police and citizen data, including criminal and biometric records, hotel and tenant registrations linked to national identity records, and personnel files. Law enforcement organizations in Balochistan, Khyber Pakhtunkhwa, Islamabad, and Punjab were confirmed as affected targets. The compromise of a Complaint Management System by China-nexus actors put both police staff and citizens' data at risk. The primary impact is the loss of sensitive internal security intelligence for Pakistan and potential privacy breaches for citizens, fueling China's independent assessment of security risks to its nationals and providing India with insights into Pakistan's security posture.

## Recommendation

* Deploy the Sigma rule "Detect Outbound Network Connections to Known Espionage C2 IPs" in this brief to your SIEM and tune for your environment.
* Block the C2 IP addresses (e.g., 172.111.233.36, 45.125.32.218, 142.171.183.8, 89.31.121.220) listed in the IOC table at the network perimeter or firewall.
* Implement robust security controls and regular patching for all externally-facing web applications, especially those managing sensitive data like the Complaint Management System.
* Conduct regular integrity checks and threat hunting on web application files and associated directories to detect unauthorized modifications or masqueraded updates.
* Monitor network traffic for outbound connections to suspicious IP addresses and known C2 infrastructure associated with PlugX, ShadowPad, Cobalt Strike, and Remcos.
