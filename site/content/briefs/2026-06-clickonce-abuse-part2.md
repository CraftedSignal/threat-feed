---
title: Threat Actors Abuse Microsoft ClickOnce Update Mechanism for Persistent Malware Delivery
slug: 2026-06-clickonce-abuse-part2
description: Threat actors are exploiting the legitimate update mechanism of Microsoft ClickOnce applications, particularly through `.appref-ms` files, to maintain persistence, bypass security controls, and deliver updated malicious payloads without requiring elevated privileges or user re-authorization on Windows systems.
date: "2026-06-21T05:21:58Z"
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
  - malware
  - social-engineering
vendors:
  - Microsoft
products:
  - Microsoft ClickOnce
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1218
    technique_name: Signed Binary Proxy Execution
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: Signed Binary Proxy Execution
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1571
    technique_name: Non-Standard Port
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect dfsvc.exe Spawning Suspicious Child Processes
    description: Detects instances where the legitimate dfsvc.exe (ClickOnce Deployment Support Service) spawns commonly abused scripting or administrative tools, which may indicate a malicious ClickOnce application payload execution. This targets the post-exploitation phase where the legitimate host launches the actual malware components.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
      - T1059.003
      - T1204.002
      - T1218
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious Outbound Network Connection by dfsvc.exe
    description: Detects when the dfsvc.exe (ClickOnce Deployment Support Service) initiates outbound network connections to non-standard ports or suspicious destinations, indicating potential C2 communication or malicious update retrieval outside of expected HTTP/HTTPS traffic to known application servers.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
      - T1571
    data_sources:
      - network_connection
      - windows
  - title: Detect Creation or Modification of Suspicious .appref-ms Files
    description: Detects the creation or modification of ClickOnce application reference files (.appref-ms) outside of typical user Start Menu paths, or by suspicious processes. This could indicate an attempt to establish persistence or execute an unauthorized ClickOnce application.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
rules_count: 3
---

Threat actors are increasingly abusing Microsoft's ClickOnce deployment technology, particularly focusing on its update mechanism, to establish persistent malware presence and evade detection. This technique, highlighted by CrowdStrike in June 2026, leverages the user-friendly installation and built-in updating features of ClickOnce to bypass traditional defenses. Attackers lure users into installing seemingly harmless ClickOnce applications, which drop `.appref-ms` shortcut files in the Start Menu. Subsequently, the threat actors can push malicious updates to these applications from their controlled deployment servers. This allows for silent malware updates, C2 address changes, and lateral movement capabilities, all while operating within legitimate Microsoft processes like `dfsvc.exe` and `rundll32.exe`. This abuse takes advantage of a general lack of awareness around ClickOnce security, providing a stealthy and persistent vector on enterprise endpoints.

## Attack Chain

1.  **Initial Access via Social Engineering:** The attacker convinces a target user, often through phishing emails or malicious websites, to click a link or button that initiates a ClickOnce application download.
2.  **Malicious ClickOnce Application Deployment:** The user's interaction triggers the download and execution of a malicious `.application` file, initiating the ClickOnce deployment process.
3.  **Execution via Legitimate Processes:** The malicious payload executes within legitimate Microsoft process trees, specifically utilizing `dfsvc.exe` (ClickOnce Deployment Support Service) and `rundll32.exe` to launch the initial malicious components.
4.  **Persistence through `.appref-ms` File:** If the application is configured for offline availability, a shortcut file (`.appref-ms`) is dropped into the user's Start Menu (`%Users\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\`).
5.  **Malicious Update Delivery:** When the user subsequently launches the application via the `.appref-ms` shortcut, the ClickOnce client checks for updates from the attacker-controlled server.
6.  **Silent Payload Update and Re-execution:** The attacker pushes a malicious update to the deployment server, which is then downloaded and executed by the `dfsvc.exe` process without requiring user re-authorization or prompting.
7.  **Impact (Remote Access/Lateral Movement):** The updated malicious payload can then establish remote access, modify C2 addresses, facilitate lateral movement, or perform other malicious actions on the compromised system.

## Impact

The successful exploitation of ClickOnce's update mechanism allows threat actors to maintain persistent access to targeted systems with high stealth. Because the initial application deployment does not require administrative privileges, standard user accounts, which comprise the majority of enterprise endpoints, are vulnerable. Once established, attackers can silently update their malware, enabling them to alter C2 infrastructure, facilitate lateral movement within a network, and exfiltrate sensitive data. This technique bypasses common email gateway protections and traditional file-based scrutiny, leading to extended dwell times and increased potential for significant data breaches or system compromise.

## Recommendation

*   **Implement a robust Endpoint Detection and Response (EDR) solution:** Deploy EDR capabilities to detect suspicious process creation and network connections from `dfsvc.exe` and `rundll32.exe` as detailed in the Sigma rules below.
*   **Deploy the Sigma rules in this brief to your SIEM/EDR:** Tune the provided rules to detect `dfsvc.exe` spawning unusual child processes or making suspicious network connections, and `rundll32.exe` executing with abnormal parameters.
*   **Monitor `process_creation` events:** Specifically watch for instances where `dfsvc.exe` or `rundll32.exe` act as parent processes for scripting interpreters (e.g., powershell.exe, cmd.exe) or other unusual executables.
*   **Monitor `network_connection` events:** Focus on outbound connections initiated by `dfsvc.exe` to non-standard ports or suspicious external IP addresses/domains.
*   **Educate users on ClickOnce risks:** Increase awareness about the nature of `.application` files and the potential risks of installing software from untrusted sources, even if the installation appears to be legitimate.
