---
title: Pelco Sarix Pro 3 Series IP Camera Authentication Bypass Vulnerability
slug: 2026-02-pelco-sarix-auth-bypass
description: An authentication bypass vulnerability (CVE-2026-1241) in the web management interface of Pelco Sarix Pro 3 Series IP Cameras (versions <= 02.52) allows unauthenticated attackers to access sensitive device data and bypass surveillance controls.
date: "2026-02-27T10:00:00Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - cve-2026-1241
  - authentication-bypass
  - ip-camera
  - ics
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-057-02
  - https://nvd.nist.gov/vuln/detail/CVE-2026-1241
  - https://www.pelco.com/support
rules:
  - title: Detect Unauthorized Access to Pelco Sarix Camera Web Interface
    description: Detects unauthorized attempts to access the web interface of Pelco Sarix IP cameras, potentially indicating exploitation of CVE-2026-1241.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - windows
  - title: Detect Configuration Changes on Pelco Sarix Cameras
    description: Detects suspicious changes to camera configuration settings via the web interface, potentially indicating unauthorized access.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

Pelco Sarix Pro 3 Series IP Cameras are affected by an authentication bypass vulnerability (CVE-2026-1241) in their web management interface. The vulnerability stems from inadequate access control enforcement, allowing unauthorized access to certain functionalities without proper authentication. This issue impacts Sarix Professional IMP 3 Series, IXP 3 Series, IBP 3 Series, and IWP 3 Series IP Cameras with firmware versions equal to or less than 02.52. Successful exploitation can lead to…
