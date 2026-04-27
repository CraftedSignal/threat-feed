---
title: Rclone Unauthenticated options/set Allows Runtime Auth Bypass
slug: 2026-04-rclone-auth-bypass
description: Rclone is vulnerable to an unauthenticated options/set vulnerability that allows runtime authentication bypass, potentially leading to sensitive operations and command execution by setting `rc.NoAuth=true` on reachable RC servers started without global HTTP authentication.
date: "2026-04-23T12:00:00Z"
severities:
  - critical
tags:
  - rclone
  - auth-bypass
  - rc-api
  - CVE-2026-41176
  - command-execution
vendors:
  - rclone
products:
  - rclone
affected_os:
  - Ubuntu
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://github.com/advisories/GHSA-25qr-6mpr-f7qx
rules:
  - title: Detect Rclone Unauthenticated options/set
    description: Detects unauthenticated POST requests to the `/options/set` endpoint of the Rclone RC API, used to disable authentication.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
  - title: Detect Rclone Core Command Execution via RC API
    description: Detects POST requests to the `/core/command` endpoint of the Rclone RC API, indicating potential command execution.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Rclone, a command-line program to manage files on cloud storage, is vulnerable to an authentication bypass via its remote control (RC) API. The vulnerability, present from version 1.45 onwards, stems from the `options/set` endpoint being exposed without authentication requirements, while still being able to modify the global runtime configuration.  An unauthenticated attacker can exploit this vulnerability by setting the `rc.NoAuth` parameter to `true`, effectively disabling the authentication…
