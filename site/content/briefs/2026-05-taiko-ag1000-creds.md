---
title: Taiko AG1000-01A SMS Alert Gateway Hardcoded Credentials Vulnerability (CVE-2026-9139)
slug: 2026-05-taiko-ag1000-creds
description: Taiko AG1000-01A SMS Alert Gateway Rev 7.3 and Rev 8 contains a hard-coded credential vulnerability (CVE-2026-9139) in the embedded web configuration interface, allowing unauthenticated attackers with network access to recover administrative credentials directly from client-side JavaScript and gain full administrative access to the device.
date: "2026-05-20T20:18:24Z"
type: threat
types:
  - threat
severities:
  - critical
tags:
  - cve
  - hardcoded-credentials
  - network-device
vendors:
  - Taiko
products:
  - AG1000-01A SMS Alert Gateway
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1556
    technique_name: Credentials from Password Stores
cves:
  - id: CVE-2026-9139
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9139
rules:
  - title: Detect Access to Taiko AG1000 Login Page
    description: Detects access to the Taiko AG1000 SMS Alert Gateway login page, potentially indicating reconnaissance activity.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1595.001
    data_sources:
      - webserver
  - title: Detect Taiko AG1000 Login Attempt with Exposed Credentials
    description: Detects requests to the Taiko AG1000 SMS Alert Gateway web interface from IPs known to host attack infrastructure.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1556.002
    data_sources:
      - webserver
rules_count: 2
---

Taiko AG1000-01A SMS Alert Gateway Rev 7.3 and Rev 8 are vulnerable to a critical security flaw (CVE-2026-9139) due to hard-coded credentials in the device's web configuration interface. The vulnerability stems from the authentication mechanism being implemented entirely in client-side JavaScript within the login.zhtml page. The static plaintext credentials are exposed directly in the page source, making them easily accessible to anyone with network access to the device. This vulnerability allows an unauthenticated attacker to recover administrative credentials and gain full administrative access, posing a significant risk to the device and potentially the wider network it is connected to.

## Attack Chain

1. Attacker gains network access to the Taiko AG1000-01A SMS Alert Gateway device.
2. Attacker navigates to the device's web configuration interface, typically accessible via a web browser.
3. The web browser downloads the login.zhtml page containing the client-side JavaScript code.
4. Attacker views the page source of login.zhtml.
5. Attacker identifies the validate() function within the JavaScript code.
6. Attacker extracts the hard-coded plaintext administrative credentials from the validate() function.
7. Attacker uses the recovered credentials to log in to the web configuration interface as an administrator.
8. Attacker gains full administrative control of the Taiko AG1000-01A SMS Alert Gateway device.

## Impact

Successful exploitation of this vulnerability grants an attacker full administrative access to the Taiko AG1000-01A SMS Alert Gateway. This could lead to unauthorized modification of device settings, disruption of SMS alert services, or potential use of the device as a pivot point for further attacks within the network. Given the critical nature of alert gateways in many operational environments, the impact could range from missed alerts to significant operational disruptions.

## Recommendation

*   Implement the following rule to detect access to the login page: "Detect Access to Taiko AG1000 Login Page".
*   Deploy the "Detect Taiko AG1000 Login Attempt with Exposed Credentials" Sigma rule to your SIEM and tune for your environment.
*   Disable the web configuration interface on Taiko AG1000-01A SMS Alert Gateway devices if it is not required.
*   Apply provided patch or upgrade to a version of Taiko AG1000-01A SMS Alert Gateway that addresses CVE-2026-9139.
