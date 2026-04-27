---
title: bsv-sdk and bsv-wallet Credential Forgery Vulnerability
slug: 2026-04-bsv-credential-forgery
description: The bsv-sdk and bsv-wallet packages are vulnerable to credential forgery because the `acquire_certificate` function persists certificate records to storage without verifying the certifier's signature, allowing attackers to forge identity certificates.
date: "2026-04-09T20:28:10Z"
severities:
  - high
tags:
  - credential-forgery
  - ruby
  - bsv-sdk
  - bsv-wallet
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://github.com/advisories/GHSA-hc36-c89j-5f4j
  - https://brc.dev/52
  - https://github.com/sgbett/bsv-ruby-sdk
rules:
  - title: Detect Direct Certificate Acquisition with Arbitrary Signature
    description: 'Detects calls to `acquire_certificate` with `acquisition_protocol: ''direct''` which could indicate an attempt to inject a forged certificate.'
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1555
    data_sources:
      - process_creation
      - linux
  - title: Detect Issuance Certificate Acquisition from Untrusted Certifier
    description: 'Detects calls to `acquire_certificate` with `acquisition_protocol: ''issuance''` targeting suspicious or untrusted certifier URLs.'
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - credential_access
    techniques:
      - T1071.001
      - T1555
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

The `bsv-sdk` and `bsv-wallet` Ruby gems are vulnerable to credential forgery due to a signature verification bypass in the `acquire_certificate` function. This function, present in both gems, persists certificate records to storage without properly verifying the certifier's signature. An attacker can exploit this vulnerability through two acquisition paths: by directly supplying certificate fields (direct path) or by controlling a certifier endpoint (issuance path). This allows the attacker to…
