---
title: GoldenEyeDog Subgroup Linked to DigiCert Breach and Code-Signing Certificate Theft
slug: 2026-07-goldeneyedog-digicert-breach
description: CylindricalCanine, a subgroup of GoldenEyeDog, breached DigiCert in April 2026 by delivering a malicious executable via a customer chat channel, leading to the theft of code-signing certificates which were then used to sign Golden Gh0st RAT malware for distribution, primarily targeting finance organizations and the gambling and gaming sectors.
date: "2026-07-17T17:29:34Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - GoldenEyeDog
tags:
  - code-signing-certificate-theft
  - supply-chain-attack
  - malware
  - rat
  - digicert
  - golden-gh0st-rat
  - apt-q-27
  - phishing
  - china
vendors:
  - DigiCert
  - GoGetSSL
  - Verokey
products:
  - Code Signing Certificates (issued by DigiCert)
  - Code Signing Certificates (issued by GoGetSSL)
  - Code Signing Certificates (issued by Verokey)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: On 2026-04-02, a threat actor contacted DigiCert's support team via a customer chat channel and delivered a ZIP file disguised as a customer screenshot.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: The file contained a .scr executable with a malicious payload.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1574
    technique_name: Hijack Execution Flow
    evidence: The end goal of the attack is to trigger a DLL side-loading chain, leveraging a legitimate executable to run a rogue DLL, while simultaneously displaying a decoy PDF document
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1553
    technique_name: Subvert Trust Controls
    evidence: CylindricalCanine has been observed abusing code-signing certificates, gaining unauthorized access to DigiCert to intercept code-signing certificates intended for DigiCert customers, and then using them to sign their own malware to avoid detection.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: The final stage is Golden Gh0st RAT, which comes with a wide array of capabilities to set up persistence
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1056
    technique_name: Input Capture
    evidence: The final stage is Golden Gh0st RAT, which comes with a wide array of capabilities to ... log keystrokes
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1057
    technique_name: Process Discovery
    evidence: The final stage is Golden Gh0st RAT, which comes with a wide array of capabilities to ... enumerate processes
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: Some of the applications it specifically targets for data collection include Skype, Google Chrome, Mozilla Firefox, 360 Secure Browser, 360 Speed Browser, and Tencent QQ Browser.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal
    evidence: The final stage is Golden Gh0st RAT, which comes with a wide array of capabilities to ... clear Windows Event logs.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1090
    technique_name: Proxy
    evidence: The final stage is Golden Gh0st RAT, which comes with a wide array of capabilities to ... start a SOCKS proxy tunnel
    confidence_band: high
references:
  - https://thehackernews.com/2026/07/goldeneyedog-subgroup-linked-to.html
rules:
  - title: Detect Suspicious .scr Executable Execution
    description: Detects the execution of .scr files, which were used by CylindricalCanine to deliver malicious payloads during the DigiCert breach. Legitimate use of .scr files is rare.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - windows
  - title: Detect Windows Event Log Clearing by 'wevtutil cl'
    description: Detects the use of 'wevtutil cl' command to clear Windows Event Logs, a common defense evasion technique used by Golden Gh0st RAT and other malware to hide activity.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1070.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CylindricalCanine, a subgroup of the Chinese cybercrime group GoldenEyeDog (also known as APT-Q-27, Dragon Breath, and Miuuti Group), was responsible for the April 2026 security incident at DigiCert. GoldenEyeDog, active since at least 2015, is known for targeting the gambling and gaming sectors, using counterfeit websites to push malware-laced software. In the DigiCert breach, CylindricalCanine accessed a support member's device by delivering a malicious payload through a customer chat channel. This access was then leveraged to steal code-signing certificates, which were subsequently used to sign Golden Gh0st RAT malware. Golden Gh0st RAT, a modified version of Gh0st RAT, is delivered via Golden Gh0st Loader and sometimes through RONINGLOADER and NSIS installers disguised as legitimate programs like Google Chrome and Microsoft Teams. The threat actor focuses on finance organizations in the Asia-Pacific region, gambling, gaming, and customer support staff in Web3 companies.

## Attack Chain

1. The threat actor contacted DigiCert's support team via a customer chat channel.
2. A ZIP file disguised as a customer screenshot, containing a malicious `.scr` executable payload, was delivered.
3. A DigiCert support analyst executed the malicious payload on their workstation, leading to system compromise.
4. The threat actor gained unauthorized access to DigiCert's internal support portal through the compromised workstation.
5. A limited function within the support portal was exploited to access initialization codes for approved but pending EV Code Signing certificate orders.
6. Approximately 60 EV Code Signing certificates were obtained and stolen from DigiCert, GoGetSSL, and Verokey certificate authorities.
7. At least 27 of the stolen certificates were weaponized by the threat actor to sign Golden Gh0st RAT and Zhong Stealer malware artifacts.
8. The digitally signed Golden Gh0st RAT malware was then distributed through various means, including phishing emails and masquerading as legitimate software, to targeted organizations for further compromise and data exfiltration.

## Impact

The breach resulted in DigiCert revoking 60 code-signing certificates, with 27 explicitly linked to the threat actor and used to sign malware artifacts such as Zhong Stealer. This incident undermines trust in the code-signing infrastructure. Successful compromise by Golden Gh0st RAT can lead to extensive data theft from applications like Skype, Google Chrome, Mozilla Firefox, 360 Secure Browser, 360 Speed Browser, and Tencent QQ Browser. The malware establishes persistence, sets up SOCKS proxy tunnels, suppresses display output, logs keystrokes, takes screenshots, enumerates processes, executes shell commands, drops additional payloads, and clears Windows Event logs, enabling comprehensive control and surveillance of the victim's system. The primary targets include finance organizations in the Asia-Pacific region, as well as companies in the gambling, gaming, and Web3 sectors.

## Recommendation

* Educate support staff on the risks of executing suspicious attachments, especially `.scr` executables, received through chat channels or emails to activate `Detect Suspicious .scr Executable Execution`.
* Deploy endpoint detection rules for unusual process activity, specifically focusing on `Detect Windows Event Log Clearing by 'wevtutil cl'`.
* Implement strict application allowlisting to prevent the execution of unauthorized `.scr` files or other executables that could lead to DLL side-loading.
* Review and enhance access controls for internal portals, especially those granting access to sensitive functions like certificate issuance.
* Monitor certificate transparency logs for newly issued or revoked certificates to identify suspicious activity.
* Implement proactive threat hunting for behaviors associated with Golden Gh0st RAT, such as keylogging, screen capture, and unusual outbound network connections.
