---
title: Avo Framework Broken Access Control Vulnerability
slug: 2024-01-03-avo-broken-access-control
description: Avo framework version 3.x contains a critical Broken Access Control vulnerability in the ActionsController. Due to insecure action lookup logic, an authenticated user can execute any Action class on any resource, even if the action is not registered for that specific resource. This leads to Privilege Escalation and unauthorized data manipulation across the entire application. Version 3.31.2 remediates this issue.
date: "2024-01-03T12:00:00Z"
severities:
  - high
tags:
  - broken-access-control
  - privilege-escalation
  - ruby
vendors:
  - rubygems
products:
  - avo
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-qc5p-3mg5-9fh8
rules:
  - title: Detect Avo Unauthorized Action Execution
    description: Detects attempts to execute Avo actions on resources where they are not explicitly registered, indicating a potential broken access control exploit.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Avo Sensitive Action Class Use
    description: Detects the use of sensitive action classes, like ToggleAdmin. This might be related to unauthorized actions.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical broken access control vulnerability exists within the Avo framework, specifically affecting version 3.x. This vulnerability resides in the `ActionsController` and stems from an insecure action lookup mechanism. An authenticated user, regardless of their privilege level, can execute any Action class (descendants of `Avo::BaseAction`) on any resource within the application. This occurs because the system fails to validate whether the requested action is legitimately registered or…
