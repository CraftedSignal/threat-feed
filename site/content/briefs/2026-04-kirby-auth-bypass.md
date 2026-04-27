---
title: Kirby CMS Authorization Bypass via Blueprint Injection
slug: 2026-04-kirby-auth-bypass
description: An authorization bypass vulnerability in Kirby CMS allows authenticated users to perform actions they should not be allowed to perform based on their configured permissions by injecting custom dynamic blueprint configuration into the model data, leading to privilege escalation.
date: "2026-04-25T12:00:00Z"
severities:
  - high
tags:
  - authorization-bypass
  - privilege-escalation
  - web-application
vendors:
  - getkirby
products:
  - Kirby CMS
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-6gqr-mx34-wh8r
  - https://github.com/getkirby/kirby/releases/tag/4.9.0
  - https://github.com/getkirby/kirby/releases/tag/5.4.0
  - https://github.com/getkirby/kirby/releases
rules:
  - title: Detect Kirby CMS Blueprint Injection
    description: Detects attempts to inject dynamic blueprint configurations into Kirby CMS during page, file, or user creation by monitoring POST requests with suspicious parameters.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Kirby CMS Unauthorized User Creation
    description: Detects attempts to create new users when the logged in user shouldn't have the permission to do so.
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

A high-severity authorization bypass vulnerability has been identified in Kirby CMS versions prior to 4.9.0 and between 5.0.0 and 5.4.0. The vulnerability allows authenticated users to perform actions they should not be authorized to perform, such as creating pages, files, or users, even if their roles lack the necessary permissions (`pages.create`, `files.create`, or `users.create`). This bypass occurs due to the injection of custom dynamic blueprint configurations into the model data during…
