---
title: BSV Ruby SDK Improper ARC Response Handling
slug: 2024-01-bsv-ruby-sdk-vuln
description: BSV Ruby SDK versions before 0.8.2 improperly handle ARC responses, treating certain failure statuses as successful broadcasts, potentially tricking applications into trusting unaccepted transactions; version 0.8.2 resolves this vulnerability.
date: "2026-04-09T18:17:03Z"
severities:
  - high
tags:
  - bsv
  - ruby
  - blockchain
  - vulnerability
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-40069
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40069
rules:
  - title: Detect BSV Ruby SDK ARC Response Errors
    description: Detects potential misuse of the BSV Ruby SDK due to improper handling of ARC responses, specifically looking for error responses that might be misinterpreted as success.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - network_connection
      - any
  - title: Detect Potentially Vulnerable BSV Ruby SDK User Agent
    description: Detects network traffic with a User-Agent header potentially indicating the use of a vulnerable BSV Ruby SDK version.
    platform: sigma
    severity: informational
    tactics:
      - reconnaissance
    techniques:
      - T1595.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The BSV Ruby SDK, a tool for interacting with the BSV blockchain, contains a vulnerability in versions prior to 0.8.2. Specifically, the `BSV::Network::ARC` component's failure detection mechanism is flawed. It only recognizes `REJECTED` and `DOUBLE_SPEND_ATTEMPTED` ARC responses as failures. Responses with `txStatus` values like `INVALID`, `MALFORMED`, `MINED_IN_STALE_BLOCK`, or any `ORPHAN`-containing string in `extraInfo` or `txStatus` are incorrectly treated as successful broadcasts. This…
