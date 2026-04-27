---
title: pyLoad Arbitrary Code Execution via Malicious Session Deserialization
slug: 2026-04-pyload-rce
description: pyLoad is vulnerable to arbitrary code execution via an unprotected `storage_folder` configuration option, allowing an attacker with `SETTINGS` and `ADD` permissions to write a malicious pickle payload to the Flask session store and execute arbitrary code upon subsequent HTTP requests.
date: "2026-04-04T06:43:37Z"
severities:
  - critical
tags:
  - pyLoad
  - rce
  - pickle
  - deserialization
  - webserver
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0006
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Indirect Command Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1566
    technique_name: Phishing
cves:
  - id: CVE-2026-33509
    cvss: 7.5
    epss: 0.00085
references:
  - https://github.com/advisories/GHSA-4744-96p5-mp2j
ioc_counts:
  hash_md5: 1
  url: 1
rules:
  - title: Suspicious pyLoad Storage Folder Modification
    description: Detects attempts to change the pyLoad storage_folder configuration to the Flask session directory, indicative of CVE-2026-35464 exploitation.
    platform: sigma
    severity: high
    tactics:
      - execution
      - persistence
    techniques:
      - T1202
      - T1547.001
    data_sources:
      - webserver
      - linux
  - title: pyLoad Malicious Session Cookie Usage
    description: Detects HTTP requests with a pyload session cookie and a request to the root path, potentially indicating deserialization of a malicious session.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1202
    data_sources:
      - webserver
      - linux
rules_count: 2
---

pyLoad, a download manager, is susceptible to arbitrary code execution due to an insecure configuration option related to the storage folder. This vulnerability arises from the incomplete fix for CVE-2026-33509. Specifically, the `storage_folder` option is not included in the `ADMIN_ONLY_OPTIONS` set, which allows users with `SETTINGS` and `ADD` permissions to modify it. By redirecting downloads to the Flask filesystem session store, an attacker can plant a malicious pickle payload as a…
