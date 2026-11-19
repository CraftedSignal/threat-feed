---
brief_id: brief-2026-11-19-geutebruck-cameras
event_id: brief-2026-11-19-geutebruck-cameras
revision: 1
activity_at: "2026-11-19T01:24:58Z"
title: 'Geutebrück IP Cameras: Remote Code Execution Vulnerabilities'
slug: 2026-11-geutebruck-cameras
description: Geutebrück IP Camera G-Cam/EFD-2250 version 1.11.0.12 contains multiple vulnerabilities, including authentication bypass and command injection, which may allow remote code execution.
date: "2026-11-19T01:24:58Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: not_observed
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:o:geutebruck:ip_camera_g-cam_efd-2250_firmware:1.11.0.12:*:*:*:*:*:*:*
  - cpe:2.3:o:geutebrueck:ip_camera_g-cam_efd-2250_firmware:1.11.0.12:*:*:*:*:*:*:*
tags:
  - CVE-2017-5173
  - CVE-2017-5174
  - remote-code-execution
vendors:
  - Geutebrück
products:
  - Geutebrück IP Camera G-Cam/EFD-2250
cves:
  - id: CVE-2017-5173
    cvss: 9.8
    epss: 0.29578
    kev_status: "false"
  - id: CVE-2017-5174
    cvss: 9.8
    epss: 0.5229
    kev_status: "false"
references:
  - https://cveawg.mitre.org/api/cve/CVE-2017-5173
  - https://cveawg.mitre.org/api/cve/CVE-2017-5174
  - https://www.cisa.gov/news-events/ics-advisories/icsa-17-045-02
---

## Overview
Geutebrück IP Camera G-Cam/EFD-2250 version 1.11.0.12 is affected by two vulnerabilities (CVE-2017-5173 and CVE-2017-5174) that may allow for remote code execution. Both vulnerabilities have a CVSS v3 base score of 9.8.

## Attack Chain
- **CVE-2017-5173:** An improper neutralization of special elements in an OS command allows an attacker to call multiple parameters, potentially providing root-level access to the operating system.
- **CVE-2017-5174:** An authentication bypass vulnerability exists within the file system architecture, which may allow attackers to bypass access control.

## Impact
Successful exploitation of these vulnerabilities may allow for unauthorized remote code execution on affected devices.

## Recommendation
Geutebrück recommends that customers download and update with the latest patches by registering for a new web club account or logging into an existing account on the vendor portal. Organizations are advised to perform an impact analysis and risk assessment before deploying defensive measures.
