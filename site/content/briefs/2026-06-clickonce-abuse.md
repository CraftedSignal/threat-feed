---
title: Threat Actors Abuse Microsoft ClickOnce for Initial Access and Persistence
slug: 2026-06-clickonce-abuse
description: Threat actors are exploiting Microsoft's ClickOnce technology to gain initial access, execute malware, and establish persistence on target systems by leveraging its user-friendly deployment model, execution within legitimate Microsoft processes, and built-in update mechanisms to bypass defenses and maintain control.
date: "2026-06-20T05:39:19Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - windows
  - persistence
  - initial-access
  - execution
  - defense-evasion
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
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Indirect Command Execution
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect ClickOnce Payload Execution via dfsvc.exe Spawning Suspicious Children
    description: Detects suspicious child processes (like rundll32.exe, PowerShell, or cmd.exe) launched by the legitimate ClickOnce Deployment Support Service (dfsvc.exe), which could indicate malicious payload execution after a ClickOnce deployment.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1059
      - T1202
    data_sources:
      - process_creation
      - windows
  - title: Detect ClickOnce Persistence via .appref-ms File Creation
    description: Detects the creation of ClickOnce application reference files (.appref-ms) in the user's Start Menu directory, a technique used by threat actors for persistence and automatic malware updates.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
  - title: Detect Suspicious ClickOnce Application Launch Command-Line
    description: Detects dfsvc.exe or rundll32.exe executing with command-line arguments that include '.application', indicating the initiation of a ClickOnce application deployment, which could be malicious if from an untrusted source.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059
      - T1566
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

Threat actors are increasingly leveraging Microsoft's ClickOnce technology for malicious purposes, exploiting its design features to achieve initial access, execute malware, and establish persistence. This method gained traction due to its minimal user interaction requirements, often bypassing traditional security controls by utilizing less scrutinized `.application` files rather than conventional executables. Attacks typically begin with social engineering, leading users to initiate a ClickOnce deployment. The inherent trust in ClickOnce allows payloads to execute within legitimate Microsoft processes like `rundll32.exe` and `dfsvc.exe`, enhancing stealth and evading detection. A significant advantage for attackers is the built-in updating mechanism: once a malicious ClickOnce application is installed and configured for offline availability, an `.appref-ms` file is dropped in the Start Menu. This file automatically triggers updates upon application launch, enabling attackers to push new malicious components, update C2 infrastructure, or facilitate lateral movement without requiring further user consent, thereby ensuring long-term persistence on compromised systems.

## Attack Chain

1.  **Initial Access via Social Engineering:** Threat actors leverage social engineering tactics (e.g., phishing emails with malicious links, weaponized websites) to entice targets into clicking on a prompt or link that initiates a ClickOnce application deployment.
2.  **ClickOnce Deployment Initiation:** The user interacts with the malicious prompt, triggering the download and execution of an `.application` file or directly initiating the ClickOnce deployment process via the `dfsvc.exe` service.
3.  **Malware Download and Execution:** The ClickOnce framework, often via `dfsvc.exe`, downloads the malicious payload (e.g., an executable, script, or DLL) and initiates its execution, frequently utilizing `rundll32.exe` to launch the payload in a stealthy manner.
4.  **Persistence Establishment:** If the deployed ClickOnce application is configured for offline use, the framework drops an `.appref-ms` shortcut file in the user's Start Menu path (`%Users\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\`) to serve as a launch point for the application.
5.  **Automated Malware Updates:** Subsequent launches of the malicious application via the `.appref-ms` shortcut trigger the ClickOnce framework to automatically check for and download updates from the attacker-controlled deployment server, refreshing or changing the malicious payload without requiring further user interaction.
6.  **Command and Control / Lateral Movement:** The updated or persistent malware establishes communication with attacker-controlled command and control (C2) infrastructure, facilitating data exfiltration, the delivery of additional payloads, or enabling lateral movement within the compromised network.
7.  **Final Objective:** The attacker achieves their final objective, which may include deploying ransomware, exfiltrating sensitive data, or using the compromised system as a pivot point for further attacks.

## Impact

The impact of ClickOnce abuse can be severe, leading to sustained compromise of target systems and networks. Since threat actors can maintain remote access and update their malware through the ClickOnce update mechanism, affected organizations face ongoing data exfiltration, the deployment of ransomware or other destructive payloads, and the use of compromised systems for lateral movement or further attacks. The stealthy nature of execution within legitimate Microsoft processes also delays detection, prolonging the dwell time of adversaries. While the brief does not specify victim counts or particular sectors, the technology's widespread use across Windows environments makes all enterprises susceptible, with financial and intellectual property theft being primary motivations.

## Recommendation

*   Enable and collect Sysmon process creation and file event logs to detect suspicious `dfsvc.exe` and `rundll32.exe` activity, particularly when associated with `.application` or `.appref-ms` files.
*   Deploy the Sigma rules in this brief to your SIEM and tune them for your environment to identify ClickOnce abuse.
*   Educate users on the risks associated with unexpected software installations and the nature of ClickOnce prompts, emphasizing caution when initiating application deployments from untrusted sources.
*   Monitor for the creation of `.appref-ms` files in user-specific Start Menu directories, as detected by the "ClickOnce Persistence via .appref-ms File Creation" rule, and investigate their origin.
