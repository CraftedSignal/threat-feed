---
title: GSuite Email with Known Abuse Web Service Links
slug: 2024-01-gsuite-abuse-links
description: This analytic detects emails in Gsuite containing links to known abuse web services such as Pastebin, Telegram, and Discord, commonly used by attackers to deliver malicious payloads leading to malware, phishing, or other harmful activities.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - gsuite
  - phishing
  - malware
  - pastebin
  - telegram
  - discord
vendors:
  - Google
products:
  - GSuite
  - Gmail
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
references:
  - https://news.sophos.com/en-us/2021/07/22/malware-increasingly-targets-discord-for-abuse/
iocs:
  - type: domain
    value: pastebin.com
  - type: domain
    value: t.me
ioc_counts:
  domain: 2
rules:
  - title: GSuite Email with Known Abuse Web Service Links
    description: Detects emails in Gsuite containing links to known abuse web services such as Pastebin, Telegram, and Discord.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - webserver
      - linux
  - title: GSuite Email with Known Abuse Web Service Links via Referrer
    description: Detects emails in Gsuite containing links to known abuse web services such as Pastebin, Telegram, and Discord via HTTP referrer
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

This threat brief focuses on the detection of malicious emails within the GSuite environment that contain links to web services known for abuse, such as Pastebin, Telegram, and Discord. These platforms are often leveraged by threat actors to host and distribute malicious payloads, phishing links, and command-and-control instructions. The detection specifically targets GSuite Gmail logs to identify emails with links containing domains associated with these services. This activity is significant because successful exploitation can lead to malware infections, credential theft, and further compromise of internal systems. The detection logic is based on identifying specific domains within email links and is designed to identify potential threats before they can be successfully executed.

## Attack Chain

1.  **Initial Access:** The attacker sends a phishing email to a target within the organization, using a GSuite account.
2.  **Delivery:** The email contains a link to a malicious payload hosted on Pastebin.
3.  **Redirection:** The user clicks on the link, redirecting them to the attacker-controlled Pastebin page.
4.  **Payload Delivery:** The Pastebin page contains obfuscated code, such as a PowerShell script, designed to download and execute a malicious payload.
5.  **Execution:** The PowerShell script executes on the victim's machine, downloading a malware stager from a Telegram channel.
6.  **Persistence:** The malware stager establishes persistence on the system.
7.  **Command and Control:** The malware establishes a command and control (C2) connection with the attacker's server, potentially using Discord as a communication channel.
8.  **Impact:** The attacker gains remote access to the compromised system, enabling data exfiltration or deployment of ransomware.

## Impact

A successful attack can lead to the compromise of sensitive information, system downtime, and financial losses. Organizations using GSuite are at risk. The impact could range from a single compromised user account to a widespread ransomware infection affecting critical business operations. Public reporting suggests similar attacks have resulted in data breaches impacting thousands of users and costing victim organizations millions of dollars in recovery efforts.

## Recommendation

*   Deploy the Sigma rule `GSuite Email with Known Abuse Web Service Links` to your SIEM to detect emails containing links to known abuse web services (Pastebin, Discord, Telegram, t.me) within GSuite Gmail logs.
*   Block the known malicious domains (pastebin.com, discord.com, telegram.org, t.me) at your organization's DNS resolver to prevent access to potentially malicious content as per the IOC table.
*   Enable GSuite Gmail logs to ensure visibility into email traffic and enable the successful operation of the detection rule detailed in this brief.
*   Implement user awareness training to educate employees about the risks associated with clicking links in emails from unknown senders, especially links to file-sharing or messaging platforms.
