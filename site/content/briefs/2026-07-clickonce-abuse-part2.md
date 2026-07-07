---
title: New Abuse of ClickOnce Technology for Stealthy Persistence
slug: 2026-07-clickonce-abuse-part2
description: Threat actors are exploiting Microsoft's ClickOnce technology, specifically abusing `.application` and `.appref-ms` files, to achieve stealthy execution and persistence without elevated privileges, enabling them to maintain remote access and update malware within legitimate Microsoft processes.
date: "2026-07-07T12:16:56Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - persistence
  - defense-evasion
  - windows
  - application-deployment
vendors:
  - Microsoft
products:
  - ClickOnce Technology
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: Threat actors only need to convince their target to click once or twice to potentially get their malware executed and persist on the target system. This option significantly simplifies the delivery phase of the kill chain as it bypasses common protection mechanisms such as mailbox filtering systems.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: To deploy a ClickOnce application, threat actors only need to convince their target to click once or twice to potentially get their malware executed and persist on the target system.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: By placing a .appref-ms file in the Startup folder or creating a scheduled task to process the file regularly, they can ensure persist
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe), increasing the stealthiness of the execution.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: ClickOnce applications also provide threat actors with a built-in updating mechanism...whoever controls the server can update the app. This gives threat actors a reliable method for maintaining remote access and updating their malware as needed to change command and control (C2) addresses.
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect ClickOnce Persistence via Startup Folder
    description: Detects the creation or modification of a ClickOnce .appref-ms shortcut file within a user's Startup folder, indicating potential persistence.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
rules_count: 1
---

CrowdStrike has identified a new abuse of Microsoft's ClickOnce technology, detailed in their June 2026 report titled 'New Abuse of the ClickOnce Technology, Part 2: Stop Threat Actors from Clicking Once and Staying Forever'. This threat leverages ClickOnce's inherent user-friendliness and low-privilege deployment to bypass traditional security controls and establish persistent access. Threat actors are weaponizing `.application` files for initial delivery and subsequently abusing `.appref-ms` shortcuts for persistence and dynamic malware updates. The attack is particularly insidious because malicious payloads execute within legitimate Microsoft processes such as `rundll32.exe` and `dfsvc.exe`, enhancing stealth and making detection challenging. This method allows adversaries to simplify malware distribution, avoid scrutiny of `exe` files, and continuously update their malicious tools without requiring user interaction or administrative rights, significantly increasing the risk of long-term compromise and remote access for targeted organizations.

## Attack Chain

1.  **Initial Access:** Threat actors conduct social engineering campaigns, often via phishing emails or malicious websites, to trick victims into clicking a link or downloading a file.
2.  **Execution (Delivery):** The victim clicks the malicious link or opens a specially crafted `.application` file, initiating the ClickOnce deployment process.
3.  **Application Installation:** The ClickOnce runtime installs a seemingly benign or malicious application, often dropping an `.appref-ms` shortcut in the user's Start Menu or similar locations if configured for offline availability, all without requiring administrator privileges.
4.  **Persistence Establishment:** The attacker leverages the `.appref-ms` file by strategically placing it in the user's Startup folder (`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`) or by creating a scheduled task to execute it regularly.
5.  **Defense Evasion (Execution):** Upon launch (either manually or via persistence), the malicious payload within the ClickOnce application executes within legitimate Microsoft processes, primarily `rundll32.exe` and `dfsvc.exe`, thereby blending into normal system activity and evading detection.
6.  **Command and Control / Updates:** The attacker maintains control over the application's deployment server. When the user launches the application, the built-in ClickOnce update mechanism downloads and executes malicious updates without further user prompts.
7.  **Impact:** This leads to established remote access, enabling data exfiltration, lateral movement, or the deployment of additional malware, ensuring long-term compromise of the target system.

## Impact

This abuse of ClickOnce technology leads to several critical impacts. Organizations targeted face a heightened risk of stealthy, persistent compromise, as attackers can maintain remote access and continually update their malware without detection. The bypass of traditional security tools, which often overlook `.application` files compared to `.exe` files, increases the success rate of initial infections. Furthermore, since these attacks do not require elevated privileges, any standard user account can be exploited, expanding the attack surface within an enterprise. The execution of malicious code within legitimate Microsoft processes significantly complicates detection and incident response efforts, allowing adversaries to remain undetected for longer periods, potentially leading to widespread data exfiltration, further lateral movement, or deployment of additional malicious payloads.

## Recommendation

*   Deploy the Sigma rule `Detect ClickOnce Persistence via Startup Folder` to identify the creation or modification of suspicious `.appref-ms` files in user Startup directories.
*   Enable detailed `file_event` logging (e.g., Sysmon Event ID 11) for paths like `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\` to monitor for new or modified `.appref-ms` files, which are central to the persistence described in the `Attack Chain`.
