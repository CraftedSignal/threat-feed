---
title: Citrix NetScaler ADC and Gateway Vulnerabilities
slug: 2026-03-citrix-netscaler-vulns
description: Citrix has released a security advisory addressing multiple vulnerabilities in NetScaler ADC and NetScaler Gateway that could lead to sensitive information disclosure and user session mix-up under specific configurations.
date: "2026-03-23T19:03:59Z"
severities:
  - medium
tags:
  - citrix
  - netscaler
  - vulnerability
  - information-disclosure
references:
  - https://cert.europa.eu/publications/security-advisories/2026-003/
rules:
  - title: Detect Suspicious HTTP Requests to NetScaler
    description: Detects suspicious HTTP requests that may indicate an attempt to exploit NetScaler vulnerabilities.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1595.002
    data_sources:
      - webserver
      - linux
  - title: Detect NetScaler Session Mix-up Attempt
    description: Detects unusual session activity indicative of a session mix-up attempt.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1078
    data_sources:
      - webserver
      - linux
rules_count: 2
---

On March 23, 2026, Citrix released a security advisory detailing several vulnerabilities affecting NetScaler ADC and NetScaler Gateway products. These vulnerabilities, if exploited, could lead to sensitive information disclosure and user session mix-up. While there is currently no evidence of active exploitation, the potential impact warrants immediate attention and remediation, particularly for internet-facing assets. The advisory urges organizations to update their affected NetScaler…
