---
title: OpenC3 COSMOS Script Runner Permissions Bypass
slug: 2024-11-openc3-cosmos-bypass
description: The OpenC3 COSMOS Script Runner widget allows authenticated users to bypass API permissions checks and execute administrative actions by running specially crafted Python and Ruby scripts, leading to data manipulation and privilege escalation.
date: "2024-11-08T12:00:00Z"
severities:
  - critical
tags:
  - openc3
  - cosmos
  - script-runner
  - permissions-bypass
  - privilege-escalation
vendors:
  - rubygems
products:
  - openc3
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-2wvh-87g2-89hr
rules:
  - title: Detect Script Runner Accessing Redis Credentials via Env
    description: Detects a Ruby script executed via the Script Runner attempting to extract Redis credentials by querying environment variables.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Detect Script Runner Writing to Redis Database
    description: Detects a Python or Ruby script executed via the Script Runner attempting to write data to the Redis database.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

The openc3-COSMOS-script-runner-api container includes a Script Runner widget that enables users to execute Python and Ruby scripts. A vulnerability exists where users with script execution privileges can bypass API permission checks due to shared networking among Docker containers. This bypass allows unauthorized administrative actions such as reading and modifying data within the Redis database, which can lead to the exposure of sensitive credentials and alteration of COSMOS settings…
