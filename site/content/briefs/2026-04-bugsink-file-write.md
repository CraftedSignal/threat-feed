---
title: BugSink Authenticated File Write Vulnerability (CVE-2026-40162)
slug: 2026-04-bugsink-file-write
description: BugSink 2.1.0 is vulnerable to an authenticated file write vulnerability (CVE-2026-40162) allowing an attacker with a valid authentication token to write arbitrary content to the filesystem, potentially leading to code execution or data compromise.
date: "2026-04-11T12:00:00Z"
severities:
  - high
tags:
  - cve-2026-40162
  - file-write
  - authentication
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
cves:
  - id: CVE-2026-40162
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40162
  - https://github.com/bugsink/bugsink/releases/tag/2.1.1
  - https://github.com/bugsink/bugsink/security/advisories/GHSA-8hw4-fhww-273g
ioc_counts:
  email: 1
rules:
  - title: Detect Suspicious BugSink File Write
    description: Detects potential exploitation of the BugSink authenticated file write vulnerability (CVE-2026-40162) by monitoring for suspicious POST requests.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - webserver
      - linux
  - title: Detect BugSink File Creation in Web Directory
    description: Detects file creation events in web directories
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - linux
rules_count: 2
---

BugSink, a self-hosted error tracking tool, is susceptible to an authenticated file write vulnerability in version 2.1.0. This vulnerability, identified as CVE-2026-40162, allows an attacker with a valid authentication token to write attacker-controlled content to a filesystem location writable by the BugSink process. The flaw resides in the artifact bundle assembly flow. Successful exploitation could allow an attacker to achieve arbitrary code execution on the BugSink server or compromise…
