---
title: Detecting Rare SMB Connections for Potential NTLM Credential Theft
slug: 2024-01-rare-smb-exfiltration
description: This brief details a detection strategy for rare SMB connections originating from internal networks to the internet, potentially indicating NTLM credential theft via rogue UNC path injection.
date: "2024-01-25T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - exfiltration
  - credential-access
  - windows
  - smb
  - ntlm
vendors:
  - Microsoft
  - Elastic
  - SentinelOne
products:
  - Elastic Defend
  - Microsoft Defender XDR
  - SentinelOne Cloud Funnel
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1048
    technique_name: Exfiltration Over Alternative Protocol
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1187
    technique_name: Forced Authentication
references:
  - https://www.securify.nl/en/blog/living-off-the-land-stealing-netntlm-hashes/
  - https://attack.mitre.org/techniques/T1048/
  - https://attack.mitre.org/tactics/TA0010/
  - https://attack.mitre.org/techniques/T1187/
  - https://attack.mitre.org/tactics/TA0006/
rules:
  - title: Detect SMB Connection to External IP
    description: Detects SMB connections (ports 139 or 445) originating from internal IP ranges to external IP addresses, excluding known internal and reserved IP ranges. This may indicate NTLM relay attempts.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - exfiltration
    techniques:
      - T1048
      - T1187
    data_sources:
      - network_connection
      - windows
  - title: Detect SMB Process ID 4 Connections to External IP
    description: Detects SMB connections (ports 139 or 445) originating from internal IP ranges to external IP addresses where process ID is 4. This is to monitor for forced authentication attempts.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - exfiltration
    techniques:
      - T1048
      - T1187
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

This detection strategy focuses on identifying unusual Server Message Block (SMB) traffic that originates from internal IP addresses and connects to external networks. The SMB protocol, commonly used for file and printer sharing within a network, can be exploited to exfiltrate data by injecting rogue UNC paths to capture NTLM credentials. This activity is often associated with threat actors attempting to steal credentials for lateral movement or data exfiltration. Defenders should be aware of this technique as it allows adversaries to bypass traditional security controls by leveraging a legitimate protocol for malicious purposes. This detection is relevant for environments utilizing Windows operating systems and SMB for internal network communications. The goal is to identify and alert on SMB connections to external IPs, excluding known safe ranges and legitimate business applications.

## Attack Chain

1. An attacker compromises an internal system via phishing or other means (not detailed in source).
2. The attacker injects a rogue UNC path into a document, email, or other medium.
3. A user opens the malicious document or clicks the injected link, triggering an SMB connection to a malicious external server.
4. The SMB connection attempts to authenticate with the user's NTLM credentials.
5. The attacker captures the NTLM hash from the authentication attempt.
6. The attacker attempts to crack the NTLM hash to obtain the user's password.
7. Using the cracked password, the attacker gains unauthorized access to other systems and resources on the network.

## Impact

Successful exploitation can lead to credential theft, allowing attackers to gain unauthorized access to sensitive data and systems within the organization. This can result in data breaches, financial losses, and reputational damage. The impact is significant because SMB is a common protocol within many Windows environments, making this technique highly effective if not properly monitored.

## Recommendation

*   Deploy the Sigma rule "Detect SMB Connection to External IP" to your SIEM to identify potentially malicious SMB connections to the internet. Tune the rule by excluding known good external IPs used by legitimate services.
*   Enable Sysmon Event ID 3 (Network Connection) with proper filtering to capture SMB traffic details as recommended in the linked setup guide, to enhance the fidelity of the detection.
*   Implement network segmentation to restrict SMB traffic to only necessary internal communications, reducing the attack surface and mitigating the risk of external exposure.
