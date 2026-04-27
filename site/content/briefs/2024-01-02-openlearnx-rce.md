---
title: OpenLearnX Remote Code Execution via Python Sandbox Escape
slug: 2024-01-02-openlearnx-rce
description: A critical RCE vulnerability in OpenLearnX allows for sandbox escape and arbitrary command execution in versions prior to 2.0.3.
date: "2024-01-02T18:00:00Z"
severities:
  - critical
tags:
  - rce
  - sandbox escape
  - code injection
products:
  - openlearnx
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
references:
  - https://github.com/advisories/GHSA-8h25-q488-4hxw
rules:
  - title: Detect Suspicious OpenLearnX Code Execution
    description: Detects potential exploitation attempts against OpenLearnX code execution environment by monitoring for unusual process activity originating from the OpenLearnX application.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - process_creation
      - linux
  - title: Detect OpenLearnX Sandbox Escape Attempts via Command Injection
    description: This rule detects potential sandbox escape attempts in OpenLearnX by monitoring for specific keywords and commands commonly used in command injection attacks.
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

A critical Remote Code Execution (RCE) vulnerability, tracked as CVE-2026-41900, has been identified in the OpenLearnX code execution environment. This vulnerability allows an attacker to escape the Python sandbox and execute arbitrary commands on the underlying system. The vulnerability affects OpenLearnX versions prior to 2.0.3. A patch has been released in version 2.0.3 to address this issue. This vulnerability allows attackers to potentially compromise the entire system hosting the…
