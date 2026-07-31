---
title: SolarWinds Web Help Desk Security Bypass Vulnerability
slug: 2026-07-solarwinds-whd-bypass
description: A vulnerability in SolarWinds Web Help Desk, identified as CVE-2024-28986, allows remote unauthenticated attackers to bypass security measures, potentially leading to unauthorized access.
date: "2026-07-31T09:28:23Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:solarwinds:web_help_desk:*:*:*:*:*:*:*:*
  - cpe:2.3:a:solarwinds:web_help_desk:12.8.3:-:*:*:*:*:*:*
tags:
  - web-application
  - security-bypass
  - vulnerability-management
vendors:
  - SolarWinds
products:
  - Web Help Desk
cves:
  - id: CVE-2024-28986
    cvss: 9.8
    epss: 0.84628
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2594
---

SolarWinds has disclosed a security vulnerability affecting Web Help Desk, which permits a remote, unauthenticated attacker to bypass established security controls. The flaw, tracked as CVE-2024-28986, impacts versions prior to 12.8.3. Successful exploitation of this vulnerability could allow unauthorized parties to access sensitive data or perform actions within the Web Help Desk application without legitimate credentials. This represents a significant risk for organizations that rely on the software for internal ticket management and IT service desk operations. Defenders should prioritize patching affected instances to version 12.8.3 or later to remediate the exposure.

## Impact

The vulnerability poses a substantial risk to organizations utilizing SolarWinds Web Help Desk for IT service management. If exploited, an unauthorized actor could gain access to the application, potentially leading to the exposure of internal incident reports, user credentials, or administrative configuration settings. Given the administrative nature of help desk software, successful exploitation could facilitate lateral movement into other internal systems by leveraging credentials or information harvested from the help desk platform.

## Recommendation

- Update all SolarWinds Web Help Desk instances to version 12.8.3 or later immediately to resolve CVE-2024-28986.
- Review web server access logs for anomalous requests directed at Web Help Desk, particularly those originating from untrusted or external IP addresses that attempt to access internal-only endpoints.
- Implement restrictive access controls for the Web Help Desk administrative portal, ensuring it is not directly exposed to the public internet.
