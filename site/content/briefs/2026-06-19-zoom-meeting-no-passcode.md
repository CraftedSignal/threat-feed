---
title: Unsecured Zoom Meeting Creation
slug: 2026-06-19-zoom-meeting-no-passcode
description: The creation of Zoom meetings without passcodes allows unauthorized access and disruption, known as Zoombombing, potentially leading to the exposure of sensitive information or reputational damage.
date: "2026-04-01T15:53:12Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - zoom
  - zoombombing
  - initial-access
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
    description: Detects the creation of Zoom meetings without a passcode, indicating a potential vulnerability to Zoombombing.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1133
      - T1190
    data_sources:
      - webserver
      - zoom
  - title: Zoom Meeting Creation Event
    description: Detects Zoom meeting creation events for monitoring purposes. Useful for baselining and identifying unusual patterns.
    platform: sigma
    severity: informational
    tactics:
      - initial_access
    data_sources:
      - webserver
      - zoom
rules_count: 2
---

The absence of passcodes on Zoom meetings creates a significant vulnerability, allowing malicious actors to engage in "Zoombombing." This involves unauthorized individuals disrupting meetings with offensive content or potentially gaining access to sensitive information discussed during the session. The Elastic detection rule, published initially in 2020 and updated in March 2026, aims to identify these unsecured meetings by monitoring Zoom event logs. This is especially relevant given the increased reliance on teleconferencing platforms and the potential for reputational and data security incidents arising from such breaches. The scope includes all Zoom meetings created where event logs are collected by Filebeat or a similar data collection method.

## Attack Chain

1. An attacker identifies a Zoom meeting ID without a passcode, often through social media or shared links.
2. The attacker joins the meeting using the Zoom client or web interface.
3. Once inside, the attacker disrupts the meeting by sharing offensive content (images, videos, audio) via screen sharing or chat.
4. The attacker may attempt to gather sensitive information shared during the meeting, such as personal data or confidential business details.
5. Participants react to the disruption, causing further chaos and potentially escalating the situation.
6. The meeting host is forced to end the meeting abruptly to stop the disruption, impacting productivity.
7. The incident may lead to reputational damage for the organization hosting the meeting.

## Impact

Unsecured Zoom meetings can lead to significant disruptions and potential data breaches. A single Zoombombing incident can affect dozens to hundreds of participants, leading to wasted time, emotional distress, and potential exposure of sensitive information. Organizations can suffer reputational damage if such incidents become public. The financial impact includes lost productivity and potential legal liabilities if personal data is compromised.

## Recommendation

*   Deploy the Sigma rule "Zoom Meeting with no Passcode" to detect the creation of meetings without passcodes in your environment.
*   Review Zoom account settings to enforce mandatory passcodes for all new meetings.
*   Enable the Zoom Filebeat module or similar structured data collection for comprehensive Zoom event logging.
*   Educate meeting hosts about the risks of unsecured meetings and best practices for securing their sessions.
*   Implement enhanced monitoring and alerting for Zoom meeting creation events to quickly detect and respond to any future instances of meetings being set up without passcodes.
