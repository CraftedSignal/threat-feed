---
title: Unsecured Zoom Meeting Creation
slug: 2026-06-19-zoom-meeting-no-passcode
description: The creation of Zoom meetings without passcodes allows unauthorized access and disruption, known as Zoombombing, potentially leading to the exposure of sensitive information or reputational damage.
date: "2026-04-01T15:53:12Z"
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

The absence of passcodes on Zoom meetings creates a significant vulnerability, allowing malicious actors to engage in "Zoombombing." This involves unauthorized individuals disrupting meetings with offensive content or potentially gaining access to sensitive information discussed during the session. The Elastic detection rule, published initially in 2020 and updated in March 2026, aims to identify these unsecured meetings by monitoring Zoom event logs. This is especially relevant given the…
