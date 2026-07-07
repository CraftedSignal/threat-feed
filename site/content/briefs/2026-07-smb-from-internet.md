---
title: SMB (Windows File Sharing) Activity from the Internet
slug: 2026-07-smb-from-internet
description: Detection rule identifies inbound Windows file sharing (SMB/CIFS) traffic originating from the Internet to internal hosts, posing a critical initial access risk due to potential exploitation of vulnerabilities like CVE-2017-0144 (EternalBlue).
date: "2026-07-03T15:45:05Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:microsoft:server_message_block:1.0:*:*:*:*:*:*:*
  - cpe:2.3:o:siemens:acuson_p300_firmware:13.02:*:*:*:*:*:*:*
  - cpe:2.3:o:siemens:acuson_p300_firmware:13.03:*:*:*:*:*:*:*
  - cpe:2.3:o:siemens:acuson_p300_firmware:13.20:*:*:*:*:*:*:*
  - cpe:2.3:o:siemens:acuson_p300_firmware:13.21:*:*:*:*:*:*:*
  - cpe:2.3:o:siemens:acuson_p500_firmware:va10:*:*:*:*:*:*:*
  - cpe:2.3:o:siemens:acuson_p500_firmware:vb10:*:*:*:*:*:*:*
  - cpe:2.3:o:siemens:acuson_sc2000_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:siemens:acuson_sc2000_firmware:5.0a:*:*:*:*:*:*:*
  - cpe:2.3:o:siemens:acuson_x700_firmware:1.0:*:*:*:*:*:*:*
  - cpe:2.3:o:siemens:acuson_x700_firmware:1.1:*:*:*:*:*:*:*
  - cpe:2.3:o:siemens:syngo_sc2000_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:siemens:syngo_sc2000_firmware:5.0a:*:*:*:*:*:*:*
  - cpe:2.3:o:siemens:tissue_preparation_system_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:siemens:versant_kpcr_molecular_system_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:siemens:versant_kpcr_sample_prep_firmware:*:*:*:*:*:*:*:*
tags:
  - initial-access
  - network
  - windows
  - smb
  - vulnerability
  - ms17-010
vendors:
  - Microsoft
products:
  - SMB Server
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1133
    technique_name: External Remote Services
    evidence: SMB should never be directly reachable from the Internet, as it is a primary target for exploitation by threat actors seeking initial access.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Inbound SMB from a public IP is a direct precondition for attacks such as EternalBlue (MS17-010) and related SMB remote code execution vulnerabilities.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: 'Correlate with endpoint telemetry on the destination host: look for process creation events, new services, or lateral movement activity that might indicate exploitation succeeded.'
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: 'Correlate with endpoint telemetry on the destination host: look for process creation events, new services, or lateral movement activity that might indicate exploitation succeeded.'
    confidence_band: med
cves:
  - id: CVE-2017-0144
    cvss: 8.8
    epss: 0.9923
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2017-0144
  - https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
rules:
  - title: Detect Inbound SMB Connection from Internet to Internal Host
    description: Detects network connections where SMB traffic (ports 139 or 445) originates from a public IP address and targets a private internal IP address, indicating potential unauthorized exposure or exploitation attempt against CVE-2017-0144 and related vulnerabilities.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1133
      - T1190
    data_sources:
      - network_connection
rules_count: 1
---

This brief addresses the critical security risk of Windows Server Message Block (SMB) file sharing services being directly exposed to the internet. SMB (operating on TCP ports 139 and 445) is a fundamental component of Windows networking, designed for local network communication. Its direct exposure to the public internet is a severe misconfiguration, creating a primary target for threat actors seeking initial access. This exposure is a direct precondition for exploitation of well-known vulnerabilities, such as MS17-010 (EternalBlue, CVE-2017-0144), which has been leveraged in widespread attacks like WannaCry and NotPetya. The detection focuses on network events where inbound SMB traffic originates from a public IP address destined for a private internal IP, signifying a direct internet connection to an internal SMB service. Organizations must actively prevent this exposure to mitigate significant attack vectors.

## Attack Chain

1.  **External Reconnaissance**: Threat actors conduct internet-wide scans for publicly accessible hosts with open SMB ports (TCP 139 and 445).
2.  **Initial Access**: An attacker initiates an SMB connection from a public IP address to a vulnerable internal host that has its SMB service inadvertently exposed to the internet.
3.  **Exploitation of Public-Facing Application**: The attacker leverages known critical SMB vulnerabilities (e.g., EternalBlue, MS17-010 / CVE-2017-0144) to gain remote code execution on the exposed Windows system.
4.  **Execution**: Upon successful exploitation, the attacker executes arbitrary commands, deploys backdoors, or stages additional malware on the compromised host, leading to process creation events or new services.
5.  **Persistence**: The attacker establishes a persistent foothold within the network, often by creating new services, modifying registry run keys, or using scheduled tasks to maintain access.
6.  **Impact**: The attacker proceeds with post-exploitation activities, which can include sensitive data exfiltration, deployment of ransomware (such as WannaCry or NotPetya), or lateral movement to further compromise the internal network.

## Impact

The direct exposure of SMB services to the internet has catastrophic consequences, as demonstrated by previous global cyberattacks. Successful exploitation leads to unauthenticated remote code execution (RCE) on the vulnerable Windows system, granting attackers full control. This can result in widespread network compromise, including encryption of critical data by ransomware (e.g., WannaCry, NotPetya), complete data exfiltration, system destruction, and significant operational disruption. Financial and reputational damage for affected organizations can be immense. The potential victim scope includes any organization or individual with an internet-facing SMB service, regardless of size or sector.

## Recommendation

*   Deploy the Sigma rule included in this brief to your SIEM, ensuring network flow or firewall log data is ingested and correlated.
*   Immediately close inbound TCP ports 139 and 445 at the firewall or security group level for all public-facing interfaces to prevent any inbound SMB traffic from the internet.
*   Patch CVE-2017-0144 (MS17-010) and all related SMB vulnerabilities on all Windows hosts, prioritizing those with potential internet exposure.
*   Audit all NAT and firewall rules to identify and remediate any misconfigurations that inadvertently expose internal SMB services.
*   If a detection fires from the provided Sigma rule, investigate the destination host for signs of compromise, such as unexpected processes or new services, and isolate it if necessary.
