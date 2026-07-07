---
title: New Abuse of ClickOnce Technology for Initial Access and Persistence
slug: 2026-07-clickonce-abuse
description: Threat actors are leveraging Microsoft's ClickOnce technology for initial access, persistence, and defense evasion by exploiting its user-friendly deployment, lack of user awareness, and legitimate update mechanisms to deliver and update malicious payloads without administrative privileges.
date: "2026-07-04T07:13:06Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - persistence
  - initial-access
  - defense-evasion
  - windows
  - application-deployment
vendors:
  - Microsoft
products:
  - ClickOnce
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: To deploy a ClickOnce application, threat actors only need to convince their target to click once or twice to potentially get their malware executed
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: Alternatively, ClickOnce applications can be deployed from .application files, which requires equally minimal user input and provides threat actors additional options to execute their payload.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: By placing a .appref-ms file in the Startup folder or creating a scheduled task
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Another advantage of ClickOnce applications for adversaries lies in the fact that they don’t require elevated privileges to be deployed.
    confidence_band: med
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: Signed Binary Proxy Execution
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe), increasing the stealthiness of the execution.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe), increasing the stealthiness of the execution.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: This means that every time a user starts the ClickOnce application from the Start Menu, whoever controls the server can update the app.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: ClickOnce applications also provide threat actors with a built-in updating mechanism. When configured to be available offline, an application reference file (.appref-ms) is dropped at the installation of the application in the Start Menu
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
---

CrowdStrike has identified new abuses of Microsoft's ClickOnce technology, building on previous research from Black Hat USA 2019, enabling threat actors to gain initial access, achieve persistence, and evade defenses. This attack vector simplifies malware delivery by requiring minimal user interaction, often bypassing traditional security controls like email filters. Threat actors leverage the lack of awareness surrounding `.application` files, as they can deploy malware without administrative privileges. A key abuse involves the `.appref-ms` files, which, when opened, trigger updates from a deployment server. This allows attackers to initially deploy a benign application and later push malicious updates without further user prompts, enabling persistence, remote access, C2 changes, and lateral movement. The stealth is enhanced by execution within legitimate Microsoft processes (`rundll32.exe`, `dfsvc.exe`). This method provides a powerful, low-privilege mechanism for adversaries to establish and maintain a foothold.

## Attack Chain

1.  Threat actor crafts a malicious ClickOnce application or compromises a legitimate ClickOnce server to host malware.
2.  Initial Access: Victim is lured to click a web button or execute a `.application` file, initiating the ClickOnce deployment process.
3.  Initial Deployment: A seemingly benign ClickOnce application is installed on the victim's system, not requiring administrative privileges.
4.  Persistence Establishment: For offline-enabled applications, a `.appref-ms` shortcut file is dropped in a user's Start Menu directory (e.g., `%Users \AppData\Roaming\Microsoft\Windows\Start Menu\Programs\`).
5.  Malicious Update Delivery: The threat actor pushes a malicious update to the ClickOnce deployment server, replacing or modifying the benign application.
6.  Execution of Malicious Update: When the victim launches the ClickOnce application via the `.appref-ms` shortcut, the legitimate ClickOnce update mechanism fetches and executes the malicious payload without additional user prompts.
7.  Defense Evasion and Impact: The malicious payload executes within legitimate Microsoft processes (`rundll32.exe`, `dfsvc.exe`), facilitating remote access, command-and-control (C2) changes, and lateral movement.

## Impact

The abuse of ClickOnce technology allows threat actors to establish stealthy and persistent access to victim systems. By operating without elevated privileges and executing within legitimate Microsoft processes like `rundll32.exe` and `dfsvc.exe`, these attacks are difficult to detect by traditional security tools and often evade user scrutiny. If successful, adversaries can maintain remote access, exfiltrate data, move laterally within a network, and update their malware unimpeded. The low barrier to entry and the inherent trust placed in Microsoft-signed applications make this a significant threat to organizations relying on standard endpoint protection.

## Recommendation

*   Enable `process_creation` logging for `rundll32.exe` and `dfsvc.exe` to monitor for unusual child processes or network connections, which may indicate malicious ClickOnce payload execution.
*   Focus on `file_event` logging for the creation or modification of `.appref-ms` files outside of known legitimate software installation directories (e.g., `%Users \AppData\Roaming\Microsoft\Windows\Start Menu\Programs\`) for potential persistence mechanisms.
*   Leverage network monitoring to detect suspicious outbound connections originating from processes associated with ClickOnce (`rundll32.exe`, `dfsvc.exe`) to known malicious C2 infrastructure.
*   Implement application whitelisting or strict software restriction policies to prevent the execution of ClickOnce applications from untrusted sources, thereby mitigating initial access vectors.
