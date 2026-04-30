---
title: baserCMS Pre-Auth Arbitrary Code Execution via Zip Upload (CVE-2025-32957)
slug: 2026-03-basercms-rce
description: baserCMS versions prior to 5.2.3 are vulnerable to arbitrary code execution via a crafted zip file upload through the restore function, leading to unauthenticated remote command execution on the webserver.
date: "2026-03-31T01:16:34Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - basercms
  - rce
  - cve-2025-32957
  - webserver
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
cves:
  - id: CVE-2025-32957
    cvss: 8.7
references:
  - https://basercms.net/security/JVN_20837860
  - https://github.com/baserproject/basercms/releases/tag/5.2.3
  - https://github.com/baserproject/basercms/security/advisories/GHSA-hv78-cwp4-8r7r
ioc_counts:
  email: 1
  url: 3
rules:
  - title: Detect baserCMS Restore Function Access
    description: Detects access to the baserCMS restore function, potentially indicating an attempted exploit of CVE-2025-32957.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect PHP Execution from Temporary Directory (baserCMS Exploit)
    description: Detects PHP execution from a temporary directory, which might indicate exploitation of CVE-2025-32957 in baserCMS.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

baserCMS, a website development framework, contains an arbitrary code execution vulnerability in versions prior to 5.2.3. The vulnerability, identified as CVE-2025-32957, lies within the application's restore function. This function allows users, including potentially unauthenticated users depending on configuration, to upload a .zip file. The uploaded archive is automatically extracted by the application. A PHP file within the extracted archive is then included using `require_once` without…
