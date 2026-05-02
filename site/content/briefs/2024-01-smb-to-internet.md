---
title: SMB (Windows File Sharing) Activity to the Internet
slug: 2024-01-smb-to-internet
description: This rule detects network events indicating the use of Windows file sharing (SMB or CIFS) traffic to the Internet, which is commonly exploited for initial access, backdoor deployment, or data exfiltration.
date: "2024-01-02T14:12:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - initial-access
  - exfiltration
  - network
vendors:
  - Elastic
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1048
    technique_name: Exfiltration Over Alternative Protocol
references:
  - https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
  - https://github.com/elastic/detection-rules/blob/main/rules/network/initial_access_smb_windows_file_sharing_activity_to_the_internet.toml
rules:
  - title: Detect Outbound SMB Traffic to the Internet
    description: Detects SMB traffic originating from internal IP ranges to external IP addresses, indicating potential unauthorized file sharing or command and control activity.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
      - initial_access
    techniques:
      - T1048
      - T1190
    data_sources:
      - network_connection
      - windows
  - title: Detect PAN-OS Outbound SMB Traffic to the Internet
    description: Detects SMB traffic originating from internal IP ranges to external IP addresses using PAN-OS logs, indicating potential unauthorized file sharing or command and control activity.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
      - initial_access
    techniques:
      - T1048
      - T1190
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

The provided Elastic rule identifies instances of Server Message Block (SMB), also known as Windows File Sharing, being transmitted to external IP addresses. SMB is intended for internal network communication for file, printer, and resource sharing. Exposing SMB to the internet presents a significant security risk. Threat actors frequently target and exploit SMB for initial access, deploying backdoors, or exfiltrating sensitive data. This activity warrants immediate investigation as it violates best practices and poses a direct threat to network security. The rule focuses on traffic on TCP ports 139 and 445, originating from internal IP ranges and destined for external IPs, excluding known safe IP ranges, as defined by IANA. The rule was last updated April 24, 2026.

## Attack Chain

1.  An internal host is compromised, often through phishing or other social engineering techniques.
2.  The compromised host attempts to establish an SMB connection to an external IP address on TCP ports 139 or 445.
3.  The attacker leverages the SMB protocol to attempt authentication, potentially exploiting vulnerabilities like credential stuffing or known SMB exploits.
4.  Upon successful authentication or exploitation, the attacker gains unauthorized access to shared resources or system services on the external system.
5.  The attacker may upload malicious payloads, such as malware or backdoors, via the SMB connection to the external host.
6.  The attacker uses the SMB protocol to exfiltrate sensitive data from the internal network to the external system.
7.  The attacker maintains persistence on the compromised internal host, using SMB for command and control or lateral movement.

## Impact

Compromising SMB services can lead to significant data breaches, system compromise, and potential ransomware deployment. Exposed SMB services allow attackers to gain unauthorized access to sensitive files, critical infrastructure, and internal network resources. Successful exploitation can result in complete system takeover, data exfiltration, and disruption of business operations. While the exact number of victims is unknown, the prevalence of SMB vulnerabilities and misconfigurations suggests a widespread risk across various sectors.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect SMB traffic to the internet and tune for your environment.
*   Review firewall and network configurations to ensure SMB traffic is not allowed to the Internet, and block any unauthorized outbound SMB traffic on ports 139 and 445, as identified by the rule description.
*   Investigate the source IP addresses triggering the rule, identifying internal systems initiating SMB traffic and determining if they belong to known devices or users within the organization, as described in the provided investigation guide.
*   Regularly audit network configurations and update the rule exceptions to include any legitimate device IPs to prevent false positives, as mentioned in the investigation guide.
