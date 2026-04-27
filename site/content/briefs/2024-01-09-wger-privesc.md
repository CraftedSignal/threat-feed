---
title: wger Broken Access Control in Global Gym Configuration Update Endpoint
slug: 2024-01-09-wger-privesc
description: The wger application has a broken access control vulnerability in the global gym configuration update endpoint, allowing low-privileged authenticated users to modify installation-wide configuration settings and escalate privileges.
date: "2026-04-16T01:35:16Z"
severities:
  - high
tags:
  - privilege-escalation
  - broken-access-control
  - web-application
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-xppv-4jrx-qf8m
rules:
  - title: wger GymConfig Update by Low-Privilege User
    description: Detects unauthorized modification of the GymConfig object by low-privileged users in wger via the /config/gym-config/edit endpoint.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: wger Default Gym Modified
    description: Detects modification of the default gym value.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The wger application exposes a global configuration edit endpoint at `/config/gym-config/edit` that is vulnerable to broken access control. The vulnerability exists because the `GymConfigUpdateView` uses the wrong mixin (`WgerFormMixin` instead of `WgerPermissionMixin`), preventing proper enforcement of the `config.change_gymconfig` permission. This allows a low-privileged authenticated user to modify the global `GymConfig` singleton (pk=1), triggering server-side side effects via the…
