---
brief_id: brief-2024-11-02-outlook-home-page-registry-modification
event_id: brief-2024-11-02-outlook-home-page-registry-modification
revision: 2
activity_at: "2024-11-02T14:30:00Z"
revision_history:
  - revision: 2
    at: "2026-10-20T13:19:21Z"
    checksum: sha256:16abebbfb14c4e66f066cb20f0d9b88e03c074274a500985dc1ea0207a59b02d
    summary: Repaired a legacy canonical identity collision
    changed_fields:
      - slug
    maintenance: true
title: Outlook Home Page Registry Modification for Command and Control and Persistence
slug: 2024-11-02-outlook-home-page-registry-modification
description: Adversaries can modify Outlook Home Page registry settings to inject malicious content, enabling command and control or persistence, detected by monitoring specific registry keys for unusual URL or path values.
date: "2024-11-02T14:30:00Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
tags:
  - outlook
  - registry
  - command-and-control
  - persistence
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
references:
  - https://cloud.google.com/blog/topics/threat-intelligence/breaking-the-rules-tough-outlook-for-home-page-attacks/
  - https://github.com/trustedsec/specula
rules:
  - title: Outlook Home Page Registry Modification
    description: Detects modifications to Outlook Home Page registry keys pointing to suspicious URLs or file paths.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
      - persistence
    techniques:
      - T1071.001
      - T1547.001
    data_sources:
      - registry_set
      - windows
  - title: Suspicious Process Creation from Outlook After Registry Modification
    description: Detects suspicious process creations spawned by Outlook after a registry modification related to the Home Page functionality.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers can abuse the Outlook Home Page functionality by modifying specific registry keys to point to attacker-controlled content. This technique allows for command and control or persistence by injecting malicious HTML, scripts, or executables into Outlook's interface. The targeted registry keys reside under `*\SOFTWARE\Microsoft\Office\*\Outlook\Webview\*` and `*\SOFTWARE\Microsoft\Office\*\Outlook\Today\*`. This technique is known to be used in conjunction with tools like Specula, which leverages COM server abuse via loopback or localhost URLs. Defenders should be aware of unauthorized modifications to these registry keys, especially when the data strings contain external URLs, local HTML files, or UNC paths, as these could be indicators of malicious activity. The Elastic detection rule `ac5a2759-5c34-440a-b0c4-51fe674611d6` detects this behavior across various Windows environments.

## Attack Chain

1.  The attacker gains initial access to the target system, potentially through phishing or exploiting a vulnerability.
2.  The attacker identifies the Outlook Home Page registry keys (`*\SOFTWARE\Microsoft\Office\*\Outlook\Webview\*` or `*\SOFTWARE\Microsoft\Office\*\Outlook\Today\*`).
3.  Using a script or tool, the attacker modifies the registry values associated with the Outlook Home Page, specifically targeting the data strings.
4.  The attacker sets the registry data to a malicious URL, file path, or UNC path pointing to attacker-controlled content. This may include a local HTML file containing malicious JavaScript or a UNC path hosting an executable.
5.  When Outlook is opened or restarted, it attempts to load the content specified in the modified registry values.
6.  If the content is a URL, Outlook will attempt to connect to the specified web server. If it is a local HTML file, Outlook will render the HTML, potentially executing malicious scripts.
7.  The malicious content executes, establishing a reverse shell or downloading additional malware.
8.  The attacker maintains persistence and/or establishes command and control over the compromised system via the injected content.

## Impact

A successful attack using Outlook Home Page modification can lead to persistent command and control within the victim's environment. Attackers can use this technique to execute arbitrary code, steal credentials, or move laterally within the network. Given the widespread use of Outlook in enterprise environments, this technique can potentially affect numerous users and systems, resulting in significant data loss and operational disruption.

## Recommendation

*   Deploy the Sigma rule `Outlook Home Page Registry Modification` to your SIEM to detect suspicious registry modifications related to Outlook Home Page settings.
*   Enable Sysmon registry event logging to collect the necessary data for the Sigma rules to function correctly.
*   Investigate any alerts generated by the Sigma rules, focusing on the `registry.path`, `registry.value`, and `registry.data.strings` fields to identify the modified settings.
*   Monitor process creation events for unusual processes spawned by Outlook (`outlook.exe`) after the registry modification event.
*   Implement strict policies regarding the use of Outlook Home Page functionality, and consider disabling it entirely if it is not required.
*   Use network monitoring to detect connections to suspicious or unknown domains and IPs originating from Outlook processes.
