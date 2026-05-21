---
title: Microsoft Takedown of SignSpaceCloud and Secure Messaging Concerns
slug: 2026-05-signspace-takedown
description: Microsoft disrupted SignSpaceCloud, a Russian cybercrime service providing code signing certificates to malware and ransomware operators, while European governments are shifting from Signal and WhatsApp due to phishing and data sovereignty risks, and the Fast16 malware targeted Iran's nuclear program.
date: "2026-05-21T06:26:52Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ransomware
  - code-signing
  - supply-chain
vendors:
  - Microsoft
  - Signal Foundation
  - WhatsApp
  - SentinelOne
  - Symantec
products:
  - Signal
  - WhatsApp
  - LS-DYNA
  - AUTODYN
  - SignSpaceCloud
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
references:
  - https://news.risky.biz/srsly-risky-biz-politicians-to-ditch-signal-for-homegrown-apps/
iocs:
  - type: domain
    value: signspace[.]cloud
ioc_counts:
  domain: 1
rules:
  - title: Detect Execution of Signed Binary from Suspicious Location
    description: Detects the execution of a signed binary from a suspicious or unusual location, indicating potential malware activity using code signing.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1553.002
    data_sources:
      - process_creation
      - windows
  - title: Detect Device Linking Phishing Lure
    description: Detects potential Signal phishing attacks using the device-linking feature, monitoring for abnormal QR code usage.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

Microsoft has taken action against SignSpaceCloud, a Russian cybercrime service operating from the domain signspace[.]cloud. This service was selling code signing certificates which were then used by malware and ransomware gangs to sign their malicious payloads, thus increasing the likelihood of bypassing security controls. The takedown involved legal action and seizure of domains and server infrastructure. This action aims to disrupt the cybercrime ecosystem by removing a key service that facilitates malware distribution.

European governments are increasingly concerned about the security and sovereignty of communications conducted via popular encrypted messaging apps like Signal and WhatsApp. There is a growing concern that politicians are using these apps for sensitive communications, making them a target for state-backed hackers, particularly through sophisticated phishing attacks that exploit the device-linking feature. Germany, France, Belgium, and Poland are developing sovereign solutions based on the Matrix protocol to address these concerns. The previous Fast16 malware targeted LS-DYNA and AUTODYN, two software applications that simulate real-world events.

## Attack Chain

1.  Malware developers acquire code signing certificates from SignSpaceCloud.
2.  Malware and ransomware payloads are signed with the acquired certificates.
3.  Signed malware is distributed through various means (e.g., compromised websites, malicious attachments).
4.  Victims unknowingly download and execute the signed malware.
5.  The malware bypasses initial security checks due to the valid code signature.
6.  Malware establishes persistence and begins malicious activities (e.g., data encryption, exfiltration).
7.  Ransomware demands are issued to victims for decryption keys.
8.  Exfiltrated data may be sold or used for further extortion.

## Impact

The availability of code signing certificates from services like SignSpaceCloud significantly increases the success rate of malware and ransomware attacks. Signed malware is more likely to bypass security controls and infect systems, leading to data breaches, financial losses, and reputational damage. The disruption of SignSpaceCloud should reduce the effectiveness of malware campaigns relying on these certificates. The Fast16 malware targeting of Iran's nuclear program aimed to waste time, resources, and lower the overall morale of the program.

## Recommendation

*   Block the domain `signspace[.]cloud` at the network perimeter to prevent access to the SignSpaceCloud service based on IOCs.
*   Implement stricter controls on code signing certificate usage and validation to prevent the execution of malware signed with compromised certificates.
*   Monitor process execution for binaries signed with untrusted or revoked certificates using endpoint detection and response (EDR) solutions.
*   Deploy network monitoring to detect suspicious activity based on the detection rules to identify malware leveraging code signing certificates.
