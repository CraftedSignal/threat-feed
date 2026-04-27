---
title: Heimdall Authorization Bypass via Case-Sensitive URL-Encoded Slash Handling
slug: 2024-01-03-heimdall-url-encoding
description: Heimdall versions before 0.17.14 are vulnerable to inconsistent path interpretation due to case-sensitive handling of URL-encoded slashes; when `allow_encoded_slashes` is set to `off` (the default), the lowercase `%2f` is not recognized, potentially leading to authorization bypass if the default rule is overly permissive and the upstream service interprets `%2f` as a path separator.
date: "2024-01-03T12:00:00Z"
severities:
  - high
tags:
  - heimdall
  - authorization-bypass
  - url-encoding
vendors:
  - dadrus
products:
  - Heimdall (versions prior to 0.17.14)
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-43jv-5j4x-qv67
rules:
  - title: Detect HTTP Requests with Lowercase URL-Encoded Slash to Heimdall
    description: Detects HTTP requests containing lowercase URL-encoded slashes (%2f) in the URI, potentially indicating an attempt to exploit the Heimdall authorization bypass vulnerability.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Heimdall Startup with Insecure Flags
    description: Detects Heimdall instances started with the `--insecure` or `--insecure-skip-secure-default-rule-enforcement` flags, which weakens security posture.
    platform: sigma
    severity: medium
    tactics:
      - configuration
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Heimdall, a cloud-native access management proxy, is susceptible to an authorization bypass vulnerability due to its case-sensitive handling of URL-encoded slashes. Specifically, versions prior to 0.17.14 fail to properly process lowercase URL-encoded forward slashes (`%2f`) when the `allow_encoded_slashes` option is disabled, which is the default configuration. This discrepancy arises because, while percent-encoding should be case-insensitive, Heimdall only recognizes the uppercase `%2F`. This…
