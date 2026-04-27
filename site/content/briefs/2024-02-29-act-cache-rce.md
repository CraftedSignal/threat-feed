---
title: act Project Cache Poisoning Vulnerability Leads to Potential RCE
slug: 2024-02-29-act-cache-rce
description: A vulnerability in versions prior to 0.2.86 of the act project allows remote attackers to create arbitrary caches, potentially leading to remote code execution within Docker containers by poisoning predicted cache keys.
date: "2026-03-31T03:15:58Z"
severities:
  - critical
tags:
  - act
  - cache-poisoning
  - rce
  - github-actions
  - linux
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
cves:
  - id: CVE-2026-34042
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34042
rules:
  - title: Detect act Cache Server Exposed on All Interfaces
    description: Detects instances of the act cache server listening on all interfaces (0.0.0.0), which is vulnerable in versions prior to 0.2.86.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    data_sources:
      - network_connection
      - linux
  - title: Detect Suspicious File Creation in Docker after act Execution
    description: Detects suspicious file creation activity within Docker containers shortly after act execution, potentially indicating code execution from a poisoned cache.
    platform: sigma
    severity: high
    tactics:
      - execution
    data_sources:
      - file_event
      - linux
rules_count: 2
---

The `act` project, designed for local execution of GitHub Actions workflows, contains a critical vulnerability affecting versions prior to 0.2.86. The built-in actions/cache server, intended for local caching, inadvertently listens for connections on all network interfaces. This exposure allows any attacker capable of reaching the server, including those on the internet, to create caches with arbitrary keys and retrieve existing cache data. By predicting the cache keys used by local actions, an…
