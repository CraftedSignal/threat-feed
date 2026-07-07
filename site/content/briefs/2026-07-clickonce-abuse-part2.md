---
title: 'New Abuse of ClickOnce Technology: Persistence via .appref-ms Files'
slug: 2026-07-clickonce-abuse-part2
description: Threat actors are actively abusing Microsoft's ClickOnce technology, enabling initial access, execution, and persistence by leveraging its user-friendly deployment, lack of user awareness, and ability to install applications without elevated privileges, often resulting in malware execution within legitimate Microsoft processes and the establishment of reliable update mechanisms for ongoing control.
date: "2026-07-07T12:50:29Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - persistence
  - execution
  - initial-access
  - microsoft
  - windows
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
    evidence: To deploy a ClickOnce application, threat actors only need to convince their target to click once or twice to potentially get their malware executed... Alternatively, ClickOnce applications can be deployed from .application files, which requires equally minimal user input.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: To deploy a ClickOnce application, threat actors only need to convince their target to click once or twice to potentially get their malware executed... users rarely realize that clicking a webpage button can trigger software installation.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: By placing a .appref-ms file in the Startup folder or creating a scheduled task to process the file regularly, they can ensure persist
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: By placing a .appref-ms file in the Startup folder or creating a scheduled task to process the file regularly, they can ensure persist
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe), increasing the stealthiness of the execution.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe)... Further, the UI displayed to the user is a legitimate one from Microsoft.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: This gives threat actors a reliable method for maintaining remote access and updating their malware as needed to change command and control (C2) addresses
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect ClickOnce .appref-ms Persistence in Startup Folders
    description: Detects the creation of a ClickOnce .appref-ms shortcut file within common Windows Startup folders, which can be used by threat actors to establish persistence and ensure malware re-execution.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
rules_count: 1
---

CrowdStrike's July 2026 report details how threat actors are actively exploiting Microsoft's ClickOnce application deployment technology to gain and maintain access to target systems. This new abuse capitalizes on ClickOnce's user-friendly installation, often requiring only one or two clicks from the user, and bypasses traditional security mechanisms that scrutinize common executable files. Attackers can deliver malicious payloads via `.application` files or misleading web buttons, leveraging the general lack of awareness around ClickOnce to slip through defenses. Crucially, deployment does not require administrator privileges, lowering the barrier for attacks. Once installed, attackers achieve persistence and maintain control through the built-in update mechanism, pushing malicious updates via compromised servers, or by placing `.appref-ms` shortcuts in Startup folders or scheduled tasks. The malicious code then executes stealthily within legitimate Microsoft processes like `rundll32.exe` and `dfsvc.exe`, increasing evasion. This attack vector, detailed in a report published June 18, 2026, presents a significant challenge for defenders.

## Attack Chain

1.  **Initial Access**: Threat actors convince a user to click a malicious link or open a seemingly benign `.application` file, often via phishing or social engineering, leveraging ClickOnce's minimal user interaction requirement.
2.  **Execution (ClickOnce Deployment)**: The user's interaction triggers the ClickOnce deployment process, which installs the application, requiring minimal user input and no elevated privileges.
3.  **Initial Malware Execution**: The malicious payload embedded within the ClickOnce application executes, often within legitimate Microsoft processes such as `rundll32.exe` or `dfsvc.exe`, aiding in defense evasion.
4.  **Persistence (Shortcut/Task)**: The attacker ensures persistence by placing an `.appref-ms` shortcut in the user's Startup folder or registering it as a scheduled task to automatically launch the malicious ClickOnce application.
5.  **Malicious Update / Re-execution**: Upon subsequent system startups or application launches via the installed shortcut/task, the ClickOnce application's update mechanism fetches updates, allowing the attacker to push further malicious components or change Command and Control (C2) addresses without further user prompting.
6.  **Command and Control / Further Actions**: The updated or re-executed malware establishes C2 to exfiltrate data, perform lateral movement, or deploy additional malware, maintaining long-term control over the compromised system.

## Impact

The observed abuse of ClickOnce technology allows threat actors to bypass common security controls, establish persistent access, and maintain remote control over victim systems. This enables them to deploy malware, exfiltrate sensitive data, and perform lateral movement within compromised networks. The ability to deploy applications without requiring administrator privileges significantly lowers the barrier for entry, making standard user accounts vulnerable. Victims experience stealthy execution as malware runs within legitimate Microsoft processes, making detection challenging and increasing the likelihood of successful long-term compromise and data loss.

## Recommendation

*   Deploy the Sigma rule "Detect ClickOnce .appref-ms Persistence in Startup Folders" to identify attempts by threat actors to establish persistence using this method.
*   Enable verbose file event logging (e.g., Sysmon Event ID 11) to capture file creations and modifications, especially in user profile and program data directories.
*   Implement application whitelisting or software restriction policies to limit the execution of unsigned or untrusted ClickOnce applications.
*   Educate users about the risks associated with clicking suspicious links or installing software from untrusted sources, even if it appears to be a legitimate application deployment.
