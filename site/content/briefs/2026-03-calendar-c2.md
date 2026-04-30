---
title: China-Nexus Campaign Using Google Calendar as C2
slug: 2026-03-calendar-c2
description: A China-nexus threat actor is utilizing Google Calendar as a command and control (C2) infrastructure to conduct stealthy operations.
date: "2026-03-21T00:00:00Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - China-nexus actor
tags:
  - google-calendar
  - c2
  - china-nexus
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1005
    technique_name: Data from Configuration Repository
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1573
    technique_name: Encrypted Channel
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://www.reddit.com/r/blueteamsec/comments/1ryo67d/google_calendar_as_c2_infrastructure_chinanexus/
  - https://www.virusbulletin.com/uploads/pdf/conference/vb2025/papers/Google-Calendar-as-C2-infrastructure-a-China-nexus-campaign-with-stealthy-tactics.pdf
rules:
  - title: Detect Google Calendar Modifications by Unusual Processes
    description: Detects processes that are not typically associated with Google Calendar making changes to calendar events.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious Google Calendar API Calls
    description: Detects network connections to Google Calendar API endpoints from unusual processes.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

A China-nexus threat actor has been observed leveraging Google Calendar as a novel command and control (C2) mechanism. This campaign, observed starting in 2025, uses calendar entries to relay commands to compromised hosts. The use of Google Calendar allows the attacker to blend in with legitimate network traffic, evade traditional C2 detection methods, and maintain persistence. The stealthy nature of this approach makes it difficult to detect and attribute. This technique is particularly concerning because it leverages a common and trusted service, making it harder to differentiate between legitimate and malicious activity. The scope of targeting is currently unknown, but the use of advanced C2 infrastructure suggests a sophisticated and potentially widespread campaign.

## Attack Chain

1.  Initial compromise occurs through an unknown vector, potentially exploiting vulnerabilities or using social engineering.
2.  A lightweight agent is installed on the target system. This agent is responsible for interacting with the Google Calendar API.
3.  The agent authenticates to a pre-configured Google account controlled by the attacker using stolen or pre-configured credentials.
4.  The agent periodically polls the Google Calendar API for new calendar events.
5.  The attacker creates calendar events containing base64-encoded commands.
6.  The agent retrieves the calendar event, decodes the command, and executes it on the compromised system.
7.  The agent transmits the results of the executed command back to the attacker, potentially through another Google service or a separate channel.
8.  The attacker uses the C2 channel to perform further actions, such as lateral movement, data exfiltration, or deployment of additional malware.

## Impact

Compromised systems could be leveraged for a variety of malicious activities, including data theft, espionage, and disruption of services. The use of Google Calendar as a C2 channel makes attribution challenging and allows the attacker to maintain a persistent presence on the compromised network. Successful attacks could lead to significant financial losses, reputational damage, and loss of sensitive information. The number of victims and specific sectors targeted are currently unknown.

## Recommendation

*   Monitor API calls to `googleapis.com` for unusual patterns or unauthorized access attempts, specifically looking for calendar event modifications from unusual user agents (reference: Attack Chain step 4).
*   Implement the Sigma rule to detect processes making modifications to Google Calendar.
*   Enable and review Google Workspace audit logs for suspicious calendar activity, including event creation and modification from unexpected locations or accounts (reference: Attack Chain step 5).
