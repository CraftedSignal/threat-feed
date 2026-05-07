---
title: WindShift OSX.WindTail Mac Implant Targeting Middle Eastern Governments
slug: 2024-01-windshift-osx-windtail
description: The APT group WindShift is targeting Middle Eastern governments with the OSX.WindTail Mac implant, which copies itself to the ~/Library/ directory, achieves persistence via login items, and has a remotely triggered self-deletion capability.
date: "2024-01-03T15:00:00Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - WindShift
tags:
  - macos
  - apt
  - windshift
  - osx.windtail
vendors:
  - Apple
products:
  - macOS
affected_os:
  - macOS
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
references:
  - https://objective-see.org/blog/blog_0x3D.html
iocs:
  - type: domain
    value: flux2key.com
  - type: domain
    value: string2me.com
ioc_counts:
  domain: 2
rules:
  - title: Detect OSX.WindTail Installation
    description: Detects OSX.WindTail malware installation by monitoring for process creation within the ~/Library/ directory.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - process_creation
      - macos
  - title: Detect OSX.WindTail C2 Beacon
    description: Detects network connection attempts to known OSX.WindTail command and control servers.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - macos
rules_count: 2
---

The APT group WindShift has been actively targeting Middle Eastern governments with a sophisticated macOS implant known as OSX.WindTail. This implant, analyzed in a two-part series, employs several techniques to establish persistence, maintain stealth, and potentially exfiltrate sensitive data. The malware uses custom URL schemes for initial infection and establishes persistence through login items. A notable feature of OSX.WindTail is its self-deletion capability, which can be triggered remotely by a command and control (C2) server. This analysis focuses on a specific sample named Final_Presentation.app (SHA1: 758F10BD7C69BD2C0B38FD7D523A816DB4ADDD90). The malware's C2 servers include flux2key.com and string2me.com. Defenders should prioritize detection and prevention measures to mitigate the risk posed by WindShift's OSX.WindTail.

## Attack Chain

1. **Initial Infection:** The user clicks a link with a custom URL scheme, triggering the malware execution.
2. **Installation:** The malware copies itself from its initial location (e.g., Desktop) to the `~/Library/` directory.
3. **Persistence:** The malware creates a login item to ensure it automatically restarts upon user login.
4. **Decryption and Configuration:** The malware decrypts strings containing file extensions of interest and C2 server information.
5. **File Enumeration:** The malware enumerates files on the system, potentially searching for files matching the decrypted file extensions (doc, docx, ppt, pdf, xls, xlsx, db, txt, rtf, pptx).
6. **C2 Communication:** The malware connects to its C2 server (`flux2key.com`) to receive commands or exfiltrate data.
7. **Self-Deletion (Conditional):** If the C2 server responds with the string "1", the malware deletes itself from the system.
8. **Termination:** After self-deletion (or if self-deletion fails), the malware terminates its process.

## Impact

Successful infection by OSX.WindTail could allow attackers to gain persistent access to sensitive government systems. This could result in the exfiltration of documents, spreadsheets, and other data. The self-deletion capability adds a layer of complexity, potentially hindering forensic investigations. The targeting of Middle Eastern governments suggests an espionage motive.

## Recommendation

*   Monitor process creation events for applications running from the `~/Library/` directory, which is an unusual location for legitimate applications (see Sigma rule: "Detect OSX.WindTail Installation").
*   Detect network connections to the known C2 domains (`flux2key.com`, `string2me.com`) using network monitoring tools or firewall logs.
*   Implement file integrity monitoring to detect changes to login items, which OSX.WindTail uses for persistence.
*   Inspect HTTP requests to `flux2key.com` for the URI path `/liaROelcOeVvfjN/fsfSQNrIyxeRvXH.php` which is used for self-deletion triggering.
*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment.
