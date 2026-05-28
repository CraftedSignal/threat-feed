---
title: GreyVibe Targets Ukraine with AI-Generated Lures and Custom Malware
slug: 2026-05-greyvibe-ai-attacks
description: The likely Russian-aligned GreyVibe group is targeting Ukrainian organizations with AI-generated lures delivered via spear-phishing and malicious websites, deploying custom malware such as PhantomRelay, LegionRelay, and FallSpy to exfiltrate sensitive data.
date: "2026-05-28T22:25:55Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - GreyVibe
tags:
  - greyvibe
  - ai-generated-lures
  - cyberespionage
  - ukraine
  - malware
  - phantomrelay
  - legionrelay
  - fallspy
vendors:
  - google
  - cloudflare
  - telegram
  - whatsapp
  - microsoft
products:
  - google drive
  - zoom
  - lapas
  - cloudflare
  - telegram
  - whatsapp
  - phantomrelay
  - legionrelay
  - fallspy
affected_os:
  - windows
  - android
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1119
    technique_name: Automated Collection
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
references:
  - https://www.bleepingcomputer.com/news/security/greyvibe-hackers-use-chatgpt-gemini-to-power-cyberattacks/
rules:
  - title: Fake Cloudflare Verification Prompt
    description: Detects execution of self-infecting commands triggered by fake Cloudflare verification prompts (PhantomClick).
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - windows
  - title: Suspicious PowerShell Network Connection
    description: Detects PowerShell scripts making network connections, indicative of potential data exfiltration or C2 activity associated with PhantomRelay or LegionRelay.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

The GreyVibe threat group, believed to be Russian-aligned, has been actively targeting Ukrainian entities since at least August 2025. WithSecure discovered this campaign in January 2026, revealing that GreyVibe leverages AI tools like ChatGPT, Ideogram AI, and Google Gemini to generate realistic lures for their cyberespionage operations. The targets include organizations in the military, government, civilian, and business sectors within Ukraine and those related to Ukraine. GreyVibe utilizes diverse attack chains, including spear-phishing (PhantomMail), fake CAPTCHA pages (PhantomClick), and malicious websites (PrincessClub, DroneLink, Nebo) to deliver custom malware such as PhantomRelay, LegionRelay, and FallSpy. The threat actor also uses AI assistance in developing malware obfuscators and RATs.

## Attack Chain

1.  **Initial Access (PhantomMail):** GreyVibe sends spear-phishing emails to Ukrainian targets using Google Drive and 4sync links, delivering malicious ZIP/RAR archives.
2.  **Deception:** Victims are presented with decoy PDF documents or fake error messages to conceal the malicious payload.
3.  **Execution (PhantomClick):** Victims are redirected to fake CAPTCHA or ClickFix pages disguised as Zoom or LAPAS sites.
4.  **Command Execution:** Targets are tricked into executing self-infecting commands via fake Cloudflare verification prompts.
5.  **Malware Installation (PrincessClub, DroneLink):** Victims visiting fake Ukrainian adult/dating websites or Ukrainian military charity websites are infected with FallSpy Android spyware and PhantomRelay/LegionRelay Windows malware.
6.  **Data Collection (FallSpy, LegionRelay):** FallSpy collects contact lists, call logs, device/network information, location data, media files, and SIM information. LegionRelay supports file theft, screenshot capturing, browser credential theft, Telegram/WhatsApp data exfiltration, and RDP access setup.
7.  **Command and Control (PhantomRelay):** PhantomRelay establishes command and control, enabling system fingerprinting, dynamic script loading, and PowerShell and Windows command execution.
8.  **Exfiltration:** Stolen data is exfiltrated to attacker-controlled servers, supporting cyberespionage objectives.

## Impact

GreyVibe's cyberespionage campaign targets Ukrainian military, government, civilian, and business sectors to gather intelligence aligned with potential Russian interests. Successful attacks can lead to the compromise of sensitive data, including personal information, military communications, and business intelligence, potentially harming national security and economic stability. The use of AI-generated lures enhances the credibility of phishing campaigns, increasing the likelihood of successful breaches. While the precise number of victims is unknown, the ongoing nature of the campaign and the breadth of targeted sectors indicate a significant and persistent threat.

## Recommendation

*   Deploy the following Sigma rule to detect the execution of self-infecting commands related to the PhantomClick campaign, triggered by fake Cloudflare verification prompts (`rules > Fake Cloudflare Verification Prompt`).
*   Monitor network connections for suspicious PowerShell commands indicative of PhantomRelay or LegionRelay activity (`rules > Suspicious PowerShell Network Connection`).
*   Enable endpoint detection and response (EDR) systems to detect and block the execution of PhantomRelay and LegionRelay, focusing on PowerShell scripts with data exfiltration capabilities.
*   Educate users about spear-phishing tactics, especially those using AI-generated lures that impersonate Ukrainian government, emergency, telecom, and energy entities (PhantomMail).
*   Implement multi-factor authentication (MFA) for all critical systems to mitigate the risk of credential theft via LegionRelay.
