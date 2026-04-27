---
title: Open WebUI Broken Access Control Vulnerability (CVE-2026-34222)
slug: 2026-04-open-webui-access-control
description: A broken access control vulnerability in Open WebUI versions prior to 0.8.11 (CVE-2026-34222) allows authenticated users to potentially access or modify tool values they should not be authorized to, leading to privilege escalation and unauthorized configuration changes.
date: "2026-04-01T18:16:29Z"
severities:
  - medium
tags:
  - broken-access-control
  - web-application
  - privilege-escalation
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1212
    technique_name: Exploitation of Credentials
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Software Discovery
cves:
  - id: CVE-2026-34222
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34222
  - https://github.com/open-webui/open-webui/releases/tag/v0.8.11
  - https://github.com/open-webui/open-webui/security/advisories/GHSA-7429-hxcv-268m
rules:
  - title: Detect Open WebUI Tool Value Modification
    description: Detects suspicious POST requests to modify tool values in Open WebUI, indicating a potential broken access control exploitation attempt.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Open WebUI Unauthorized Configuration Change
    description: Detects potential unauthorized configuration changes in Open WebUI by monitoring for specific API calls.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Open WebUI is a self-hosted artificial intelligence platform designed to operate entirely offline. Prior to version 0.8.11, a broken access control vulnerability, identified as CVE-2026-34222, exists within the application concerning tool values. An authenticated user with low privileges could potentially manipulate these tool values, leading to unintended functionality or unauthorized access to sensitive configurations. The vulnerability was reported by GitHub, Inc. and patched in version…
