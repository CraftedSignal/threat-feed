---
title: Zoom Meetings Created Without Passcodes
slug: 2024-01-29-zoom-meeting-no-passcode
description: Detection of Zoom meetings created without a passcode, which are susceptible to Zoombombing and potential disruption or exposure of sensitive information.
date: "2024-01-29T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - zoom
  - initial-access
  - configuration-audit
  - zoombombing
vendors:
  - Zoom
products:
  - Zoom Meetings
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1133
    technique_name: External Remote Services
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://blog.zoom.us/a-message-to-our-users/
  - https://www.fbi.gov/contact-us/field-offices/boston/news/press-releases/fbi-warns-of-teleconferencing-and-online-classroom-hijacking-during-covid-19-pandemic
  - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/initial_access_zoom_meeting_with_no_passcode.toml
rules:
  - title: Zoom Meeting Created Without Passcode
    description: Detects Zoom meetings created without a passcode, which are vulnerable to unauthorized access and disruption.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1133
    data_sources:
      - webserver
      - linux
  - title: Zoom Meeting Creation Event Without Password
    description: Detects zoom meeting creation without password
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1133
    data_sources:
      - webserver
      - linux
rules_count: 2
---

This brief focuses on the risk associated with Zoom meetings created without a passcode. When meetings lack this basic security measure, they become vulnerable to "Zoombombing," where unauthorized individuals disrupt the session with offensive or inappropriate content. The Elastic detection rule, published on 2026-04-10, identifies such meetings by monitoring Zoom event logs. This is particularly relevant for organizations using Zoom for internal and external communication, as the lack of a passcode can lead to reputational damage, exposure of sensitive information, and overall disruption of business operations. Ensuring that all meetings are password-protected is a simple yet effective way to mitigate this risk.

## Attack Chain

1. A Zoom meeting is created by a user without enabling the passcode feature.
2. The meeting details (including the meeting ID) are potentially shared publicly or become discoverable through automated tools.
3. Attackers or malicious actors identify the unprotected Zoom meeting.
4. Attackers join the meeting without any authentication or authorization.
5. Once inside the meeting, attackers disrupt the session by sharing inappropriate content (e.g., images, videos, audio).
6. Participants within the meeting are exposed to the offensive content, leading to disruption and potential reputational damage.
7. The meeting organizer is forced to terminate the session to stop the disruption.
8. The organization experiences a loss of productivity and may face public criticism due to the incident.

## Impact

Failure to secure Zoom meetings with passcodes can lead to significant disruptions, with potential exposure of sensitive information and reputational damage. While the exact number of victims is difficult to quantify, Zoombombing incidents have affected organizations across various sectors. Successful attacks can result in the shutdown of meetings, loss of productivity, and the need for damage control. The impact extends beyond immediate disruption to potential long-term damage to an organization's reputation and client trust.

## Recommendation

*   Deploy the Sigma rule provided below to detect Zoom meetings created without a password.
*   Enable Zoom Filebeat module to properly ingest the Zoom logs required for detection.
*   Review Zoom configuration settings to enforce mandatory passcodes for all future meetings.
*   Implement enhanced monitoring and alerting for Zoom meeting creation events to quickly detect and respond to any future instances of meetings being set up without passcodes.
*   Educate users on the importance of using passcodes for all Zoom meetings to prevent unauthorized access and potential disruptions.
