---
title: Information Disclosure Vulnerability in Rocket Remote Desktop
slug: 2026-10-rocket-remote-desktop-info-disclosure
description: Rocket Remote Desktop contains a vulnerability that allows an attacker to disclose sensitive information, specifically credentials stored within configuration files.
date: "2026-10-12T11:38:30Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:rocketsoftware:rocket_remote_desktop:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - credential-access
vendors:
  - Rocket Software
products:
  - Rocket Remote Desktop (< 2024.3.0.25206)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: An attacker can exploit the application to disclose sensitive information, specifically credentials stored within the configuration files.
    confidence_band: high
cves:
  - id: CVE-2024-5178
    cvss: 4.9
    epss: 0.33593
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3855
  - https://nvd.nist.gov/vuln/detail/CVE-2024-5178
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade Rocket Remote Desktop to version 2024.3.0.25206 or later
      owner: IT Operations
      addresses: CVE-2024-5178
      evidence: Vendor security advisory
---

Rocket Remote Desktop is susceptible to a security vulnerability (CVE-2024-5178) that enables unauthorized parties to access sensitive information. An attacker can exploit this flaw to retrieve credentials stored within the application's configuration files. This exposure can lead to the compromise of remote access sessions and persistent unauthorized access to managed infrastructure. The vulnerability affects Rocket Remote Desktop versions prior to 2024.3.0.25206. Organizations utilizing this software for remote management should prioritize patching to the latest version to prevent the unauthorized extraction of saved connection secrets.

## Impact

Successful exploitation allows an attacker to gain unauthorized access to credentials stored by Rocket Remote Desktop. This potentially impacts all sectors relying on the software for remote server management. Exposure of these credentials can facilitate lateral movement, privilege escalation, and full control over the remote systems managed by the compromised client, creating a significant risk to the security of the host environment.

## Recommendation

* Update Rocket Remote Desktop to version 2024.3.0.25206 or later immediately.
* Review access logs and configuration file modification timestamps for unauthorized access to the application data directory.
* Rotate any credentials previously stored within Rocket Remote Desktop if unauthorized access to the system is suspected.
