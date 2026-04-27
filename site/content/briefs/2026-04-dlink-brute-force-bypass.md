---
title: D-Link DWM-222W USB Wi-Fi Adapter Brute-Force Protection Bypass Vulnerability
slug: 2026-04-dlink-brute-force-bypass
description: D-Link DWM-222W USB Wi-Fi Adapter is vulnerable to brute-force attacks due to a protection bypass, allowing unauthenticated adjacent network attackers to gain control over the device by circumventing login attempt limits.
date: "2026-04-24T04:16:23Z"
severities:
  - high
tags:
  - brute-force
  - credential-access
  - network-device
vendors:
  - D-Link
products:
  - DWM-222W USB Wi-Fi Adapter
cves:
  - id: CVE-2026-6947
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6947
  - https://www.twcert.org.tw/en/cp-139-10865-de323-2.html
  - https://www.twcert.org.tw/tw/cp-132-10864-944b1-1.html
rules:
  - title: Detect Excessive Authentication Attempts
    description: Detects a high number of failed authentication attempts from the same source IP address, indicating a possible brute-force attack against a web interface.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1110.001
    data_sources:
      - webserver
      - linux
  - title: Detect High Number of Connection Attempts to Port 80/443
    description: Detects a high number of connection attempts to port 80 and 443 in a short period of time
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1110.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

The D-Link DWM-222W USB Wi-Fi Adapter is susceptible to a brute-force protection bypass vulnerability (CVE-2026-6947). This flaw allows an attacker on an adjacent network to circumvent the built-in login attempt limits. By repeatedly attempting different credentials without being blocked, an attacker can successfully brute-force the password and gain unauthorized access to the device. This vulnerability poses a significant risk as it enables attackers to potentially reconfigure the device…
