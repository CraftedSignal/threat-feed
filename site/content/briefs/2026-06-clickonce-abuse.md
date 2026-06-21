---
title: Abuse of Microsoft ClickOnce Technology for Malware Distribution
slug: 2026-06-clickonce-abuse
description: Threat actors are identified to be abusing Microsoft's ClickOnce deployment technology, leveraging its user-friendly, no-admin-privilege application deployment capabilities to distribute malware, simplifying initial access and potential persistence on target systems.
date: "2026-06-21T05:23:19Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - windows
  - malware_distribution
  - application_deployment
vendors:
  - Microsoft
products:
  - ClickOnce technology
  - Visual Studio
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
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-one/
rules:
  - title: Detect ClickOnce Application Execution from Cache
    description: Detects execution of processes from the ClickOnce application cache directory, which is a common location for both legitimate ClickOnce applications and potentially malicious ones deployed via this mechanism. This rule needs tuning to filter legitimate applications.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059
      - T1204.001
    data_sources:
      - process_creation
      - windows
  - title: Detect ClickOnce Deployment Service Spawning Suspicious Processes
    description: Detects the ClickOnce deployment service (dfsvc.exe) launching child processes that are commonly associated with attacker activity, such as command shells or scripting engines. This indicates potential abuse of ClickOnce for initial execution of payloads.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059
      - T1218
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CrowdStrike has identified new methods of abusing Microsoft's ClickOnce technology, a deployment mechanism designed to simplify application installation and updates for Windows users. While intended to facilitate software distribution by developers, its key features—minimal user interaction, no elevated privileges required for deployment, and self-updating functionality—make it an attractive vector for threat actors. By packaging malicious applications as ClickOnce deployments, attackers can bypass traditional security controls that rely on administrative prompts, enabling easy initial access and persistent execution on victim systems. This analysis, part one of a series, details the internal workings of ClickOnce, setting the stage for understanding how attackers weaponize this legitimate technology to distribute malware effectively.

## Attack Chain

1.  Attacker crafts a malicious Windows application, potentially using development tools like Visual Studio, and publishes it as a ClickOnce application.
2.  The attacker hosts the generated ClickOnce deployment manifest (`.application` file) and associated application files on an attacker-controlled web server or file share.
3.  The victim is enticed through social engineering (e.g., phishing email, malicious website, deceptive advertisement) to click a link pointing to the hosted `.application` manifest.
4.  Upon clicking the link, the Windows operating system downloads the deployment manifest and prompts the user for confirmation to install or run the ClickOnce application, especially if the publisher is untrusted.
5.  If the user confirms, the ClickOnce deployment service (`dfsvc.exe` or `rundll32.exe` loading `dfshim.dll`) downloads the malicious application files to the user's ClickOnce application cache (`%LOCALAPPDATA%\Apps\2.0\` directory).
6.  The malicious application executes directly from the ClickOnce cache without requiring elevated privileges, blending in with legitimate ClickOnce applications.
7.  The executed malicious application proceeds to establish persistence, perform data exfiltration, execute further payloads, or otherwise compromise the system.
8.  Leveraging ClickOnce's self-updating feature, the attacker can maintain persistence or update their malware without further user interaction, fetching new payloads from the controlled server.

## Impact

Successful exploitation of ClickOnce technology allows attackers to bypass typical administrative privilege requirements for software installation, leading to widespread and low-friction malware distribution. Victims may experience system compromise, data theft, credential harvesting, or further network lateral movement. The ease of deployment means that targeted users, regardless of their technical proficiency, are susceptible to inadvertently installing malicious software, potentially impacting individuals across various sectors through broad phishing campaigns.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment, focusing on `process_creation` and `network_connection` logs from Windows endpoints.
*   Educate users on the risks of running unsigned or untrusted ClickOnce applications, emphasizing caution when prompted for installation.
*   Monitor for `dfsvc.exe` and `rundll32.exe` processes creating child processes or making network connections to suspicious or unapproved external domains.
*   Implement application whitelisting solutions to prevent execution of unknown executables from user-writable paths like `%LOCALAPPDATA%\Apps\2.0\`.
