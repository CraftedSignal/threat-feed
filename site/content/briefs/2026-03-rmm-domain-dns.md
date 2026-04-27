---
title: DNS Queries to RMM Domains from Non-Browser Processes
slug: 2026-03-rmm-domain-dns
description: Detection of DNS queries to known remote monitoring and management (RMM) domains originating from non-browser processes on Windows systems indicates potential abuse of legitimate software for command and control.
date: "2026-03-24T12:00:00Z"
severities:
  - medium
tags:
  - rmm
  - command-and-control
  - windows
references:
  - https://attack.mitre.org/techniques/T1219/002/
  - https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a
ioc_counts:
  domain: 74
rules:
  - title: DNS Query to Known RMM Domain from Non-Browser Process
    description: Detects DNS queries to known RMM domains from processes excluding common web browsers.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    data_sources:
      - dns_query
      - windows
  - title: Process Connecting to Known RMM Domain
    description: Detects a non-browser process initiating a network connection to an IP address associated with a known RMM domain.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

This brief focuses on the abuse of legitimate Remote Monitoring and Management (RMM) software by threat actors. RMM tools are often used for legitimate IT administration but can be leveraged for malicious purposes such as command and control, persistence, and lateral movement within a compromised network. This activity is identified by detecting DNS queries to a list of known RMM service domains originating from processes that are not typical web browsers. This behavior indicates that an RMM…
