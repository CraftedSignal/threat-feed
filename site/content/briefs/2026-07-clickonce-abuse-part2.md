---
title: Threat Actors Weaponize Microsoft ClickOnce for Initial Access, Persistence, and Updates
slug: 2026-07-clickonce-abuse-part2
description: Threat actors are exploiting Microsoft's ClickOnce technology, specifically by leveraging `.application` files and manipulating `.appref-ms` shortcuts for initial access, stealthy persistence within legitimate Microsoft processes, and maintaining remote access through the built-in update mechanism, bypassing traditional security controls.
date: "2026-07-06T08:32:33Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - persistence
  - initial-access
  - windows
  - defense-evasion
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: To deploy a ClickOnce application, threat actors only need to convince their target to click once or twice to potentially get their malware executed and persist on the target system.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: By placing a .appref-ms file in the Startup folder or creating a scheduled task, adversaries can automate their opening to use them as intermediaries, rather than directly running malicious payloads.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe), increasing the stealthiness of the execution.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: ClickOnce applications also provide threat actors with a built-in updating mechanism. ... whoever controls the server can update the app. This gives threat actors a reliable method for maintaining remote access and updating their malware as needed.
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect ClickOnce Appref-ms Persistence via Startup Folder
    description: Detects the creation or modification of a ClickOnce application shortcut (.appref-ms) in a user's Startup folder for persistence. Threat actors use this to automatically launch malicious ClickOnce apps upon login.
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
  - title: Detect ClickOnce Application Execution by rundll32.exe or dfsvc.exe
    description: Detects suspicious execution of ClickOnce related files (.application or .appref-ms) by rundll32.exe or dfsvc.exe, which threat actors use to execute malicious payloads under legitimate processes.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1059
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Threat actors are increasingly abusing Microsoft's ClickOnce deployment technology to bypass security defenses, achieve persistence, and maintain access to target systems. This new abuse, documented in Part 2 of CrowdStrike's analysis, highlights how the user-friendly nature of ClickOnce, which requires minimal interaction to install applications, is being weaponized. Attackers convince users to click on malicious links or `.application` files, leading to the deployment of malware. A key technique involves manipulating `.appref-ms` files, which are shortcuts for offline ClickOnce apps, placing them in locations like the Startup folder or creating scheduled tasks to trigger them. This allows the malicious application to execute within legitimate Microsoft processes such as `rundll32.exe` and `dfsvc.exe`, increasing stealth. Furthermore, the built-in update mechanism of ClickOnce is exploited to dynamically update malware or change command and control infrastructure, presenting a significant challenge for defenders unaware of this vector.

## Attack Chain

1.  **Initial Access (Phishing/Malicious Download):** Threat actors deliver a malicious link or `.application` file via phishing emails, compromised websites, or other social engineering tactics, convincing users to click it.
2.  **Execution (ClickOnce Deployment):** The user clicks the link or opens the `.application` file, triggering the ClickOnce deployment process, which downloads and installs the attacker's malicious application.
3.  **Persistence (Appref-ms Manipulation):** The malicious ClickOnce application either drops a manipulated `.appref-ms` shortcut file into the user's Startup folder (`%Users%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\`) or creates a scheduled task to launch the `.appref-ms` file.
4.  **Defense Evasion (Legitimate Process Execution):** The ClickOnce application, including its malicious payload, executes under legitimate Microsoft processes like `rundll32.exe` or `dfsvc.exe`, blending in with normal system activity and evading typical behavioral detection.
5.  **Command and Control (Update Mechanism):** The attacker leverages the inherent update mechanism of the ClickOnce application, controlled via the deployment server, to fetch new malware components, change C2 addresses, or receive further instructions.
6.  **Impact (Remote Access/Exfiltration):** With persistent access and update capabilities, the attacker can establish long-term remote access, exfiltrate sensitive data, move laterally within the network, or deploy additional malware.

## Impact

The observed impact of ClickOnce abuse includes successful initial access, persistent presence on compromised endpoints, and the ability to maintain and update malicious payloads. By exploiting the trusted nature and minimal user interaction of ClickOnce, threat actors can bypass email filtering and endpoint security solutions that focus on traditional executable files. This technique allows adversaries to establish stealthy remote access, exfiltrate sensitive information, and further compromise targeted networks without requiring elevated privileges. The lack of widespread awareness about ClickOnce as an attack vector means that many organizations may be vulnerable to these tactics, potentially leading to widespread data breaches and system compromise if not adequately defended against.

## Recommendation

*   Deploy the Sigma rule detecting suspicious `.appref-ms` creation for persistence to your SIEM and tune it for your environment.
*   Enable Sysmon file creation and registry modification logging to capture `file_event` and `registry_set` data necessary for the provided rules.
*   Educate users on the risks of clicking on unexpected links or opening `.application` files, even if they appear to originate from trusted sources.
*   Monitor process creation logs for `rundll32.exe` and `dfsvc.exe` executions that originate from unusual parent processes or execute `.application` or `.appref-ms` files.
