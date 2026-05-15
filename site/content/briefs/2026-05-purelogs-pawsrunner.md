---
title: PureLogs Infostealer Delivered via PawsRunner Steganography
slug: 2026-05-purelogs-pawsrunner
description: A steganography-based malware campaign uses PawsRunner to deliver the PureLogs infostealer, highlighting evolving delivery methods.
date: "2026-05-15T16:02:26Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - steganography
  - infostealer
  - malware
products:
  - PureLogs
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
references:
  - https://feeds.fortinet.com/~/956103044/0/fortinet/blog/threat-research~PureLogs-Delivery-via-PawsRunner-Steganography
rules:
  - title: Detect PawsRunner Execution
    description: Detects the execution of PawsRunner, a tool used in the PureLogs steganography campaign.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566
    data_sources:
      - process_creation
      - windows
  - title: Process Creation from Unusual Image Paths
    description: Detects process creation events originating from image file paths, which may indicate steganography-based malware execution.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1027
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

FortiGuard Labs has identified a new malware campaign in May 2026 employing steganography to deliver the PureLogs infostealer. This campaign leverages PawsRunner, a tool likely used to facilitate the execution or delivery of the payload embedded within the steganographic image. The use of steganography allows attackers to conceal malicious code within seemingly benign image files, evading traditional signature-based detection methods. This shift in delivery mechanism requires defenders to adapt and implement more sophisticated detection strategies focused on identifying anomalous behavior related to image processing and execution of hidden payloads.

## Attack Chain

1.  The attack begins with the victim receiving a seemingly harmless image file, potentially through email or a compromised website.
2.  The image file contains a hidden PureLogs infostealer payload embedded using steganographic techniques.
3.  PawsRunner, a tool not fully detailed in the source, is employed to extract and execute the concealed PureLogs payload from the image.
4.  PureLogs, once executed, begins collecting sensitive information from the compromised system.
5.  The infostealer gathers credentials, browser data, cookies, and other sensitive information.
6.  PureLogs establishes a connection to a command-and-control (C2) server to exfiltrate the stolen data.
7.  The attacker receives the exfiltrated data, enabling them to perform further malicious activities such as account compromise, identity theft, or financial fraud.

## Impact

A successful attack leads to the compromise of sensitive user data, including credentials, browsing history, and potentially financial information. The number of victims and specific sectors targeted are not detailed in the source. However, the deployment of an infostealer like PureLogs can result in significant financial losses, reputational damage, and potential legal liabilities for affected organizations.

## Recommendation

*   Implement anomaly detection on image processing to identify unusual activities like execution of code from image files (refer to the Sigma rule detecting process creation from unusual image paths).
*   Monitor network traffic for connections to known command-and-control (C2) infrastructure associated with PureLogs if additional IOCs become available.
*   Implement and tune the provided Sigma rule to detect the execution of PawsRunner, which is used to extract and execute the concealed PureLogs payload.
