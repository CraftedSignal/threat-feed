---
title: ZKTeco CCTV Authentication Bypass Vulnerability
slug: 2026-05-zkteco-cctv-auth-bypass
description: ZKTeco CCTV cameras are vulnerable to authentication bypass due to an undocumented configuration export port that does not require authentication and exposes critical information about the camera, such as open services and account credentials, as tracked by CVE-2026-8598.
date: "2026-05-19T16:16:31Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - cve
  - authentication-bypass
  - information-disclosure
vendors:
  - ZKTeco
products:
  - ZKTeco CCTV Cameras
  - ZKTeco SSC335-GC2063-Face-0b77 Solution
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-139-04
  - https://www.cve.org/CVERecord?id=CVE-2026-8598
  - https://www.zkteco.com/en/announcement/23
iocs:
  - type: url
    value: https://www.zkteco.com/en/announcement/23
ioc_counts:
  url: 1
rules:
  - title: Detect ZKTeco Camera Configuration Port Access
    description: Detects CVE-2026-8598 exploitation - connection attempts to ZKTeco camera configuration port (80, 8080, 443) from unusual sources.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1040
    data_sources:
      - network_connection
      - windows
  - title: Detect ZKTeco Camera Configuration Port Access (Linux)
    description: Detects CVE-2026-8598 exploitation - connection attempts to ZKTeco camera configuration port (80, 8080, 443) from unusual sources on Linux
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1040
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

An authentication bypass vulnerability exists in ZKTeco CCTV cameras, specifically affecting the SSC335-GC2063-Face-0b77 Solution versions prior to V5.0.1.2.20260421. CVE-2026-8598 describes how an undocumented configuration export port is accessible without authentication, which exposes critical information, including camera account credentials and open services. Successful exploitation of this vulnerability allows unauthorized access to sensitive camera data. This vulnerability was reported to CISA by Souvik Kandar. ZKTeco released a patch in firmware version V5.0.1.2.20260421.

## Attack Chain

1.  Attacker identifies a vulnerable ZKTeco CCTV camera exposed on a network.
2.  Attacker sends a request to the undocumented configuration export port.
3.  The camera responds with a configuration file without requiring authentication.
4.  Attacker parses the configuration file.
5.  Attacker extracts sensitive information, including camera account credentials, from the configuration file.
6.  Attacker uses the obtained credentials to access the camera's management interface.
7.  Attacker gains unauthorized access to live video feeds and camera settings.

## Impact

Successful exploitation of CVE-2026-8598 can lead to unauthorized access to sensitive video and audio data. This may result in privacy violations, intellectual property theft, or facilitate further malicious activities, such as physical intrusions. The vulnerability affects ZKTeco CCTV cameras deployed worldwide, including in commercial facilities.

## Recommendation

*   Upgrade ZKTeco CCTV cameras to firmware version V5.0.1.2.20260421 or later to remediate CVE-2026-8598.
*   Use the IOC URL `https://www.zkteco.com/en/announcement/23` to monitor for updates and further information from ZKTeco.
*   Enable network monitoring to detect suspicious connections to undocumented ports on ZKTeco cameras and deploy the Sigma rule to detect connections to common ports used by these devices.
