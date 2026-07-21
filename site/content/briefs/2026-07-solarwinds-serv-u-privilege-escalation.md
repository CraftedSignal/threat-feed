---
title: SolarWinds Serv-U Privilege Escalation Vulnerability (CVE-2026-28310)
slug: 2026-07-solarwinds-serv-u-privilege-escalation
description: CVE-2026-28310 describes a critical privilege escalation vulnerability (CVSS 9.1) affecting SolarWinds Serv-U versions 15.5.4 HF1 and below, allowing a domain administrator to elevate their user type to that of a system administrator, with lower impact noted in Windows deployments.
date: "2026-07-21T16:25:43Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - privilege-escalation
  - server-software
  - vulnerability
vendors:
  - SolarWinds
products:
  - Serv-U 15.5.4 HF1 and below
affected_os:
  - Windows
  - Linux
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: SolarWinds Serv-U is affected by a privilege escalation vulnerability that allows a domain administrator to escalate their user type to that of a system administrator.
    confidence_band: high
cves:
  - id: CVE-2026-28310
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-28310
  - https://documentation.solarwinds.com/en/success_center/servu/content/release_notes/servu_2026-3_release_notes.htm
  - https://www.solarwinds.com/trust-center/security-advisories/CVE-2026-28310
iocs:
  - type: url
    value: https://documentation.solarwinds.com/en/success_center/servu/content/release_notes/servu_2026-3_release_notes.htm
  - type: url
    value: https://www.solarwinds.com/trust-center/security-advisories/CVE-2026-28310
ioc_counts:
  url: 2
---

A critical privilege escalation vulnerability, identified as CVE-2026-28310, has been discovered in SolarWinds Serv-U versions 15.5.4 HF1 and earlier. This flaw allows an authenticated domain administrator to escalate their privileges to that of a system administrator, gaining full control over the Serv-U instance. The vulnerability has a CVSS v3.1 base score of 9.1, indicating its critical severity. While the issue impacts both Windows and Linux deployments of Serv-U, the overall impact is considered lower in Windows environments. This vulnerability is due to missing authorization (CWE-862) which allows an already authenticated user with domain administrator privileges to bypass security controls and obtain higher-level access. Defenders need to prioritize patching to prevent unauthorized administrative control.

## Attack Chain

1. An attacker, already possessing valid domain administrator credentials for the environment where SolarWinds Serv-U is deployed, authenticates to the Serv-U application.
2. Leveraging the missing authorization vulnerability (CWE-862) within Serv-U, the domain administrator user exploits the flaw.
3. The exploitation of CVE-2026-28310 results in the elevation of the domain administrator's user type within Serv-U to that of a system administrator.
4. The now system administrator user gains full administrative control over the Serv-U application, its configurations, and potentially managed files.

## Impact

Successful exploitation of CVE-2026-28310 grants an attacker with domain administrator privileges complete control over the compromised Serv-U application as a system administrator. This level of access could lead to unauthorized modification of server configurations, data exfiltration from files managed by Serv-U, disruption of file transfer services, or the use of the server as a platform for further internal network attacks. While the impact is stated to be lower in Windows deployments, the potential for significant unauthorized access and control remains critical for all affected organizations using Serv-U.

## Recommendation

* Immediately patch SolarWinds Serv-U to a version beyond 15.5.4 HF1, as indicated by the SolarWinds release notes referenced in the brief for CVE-2026-28310.
* Review access logs for Serv-U to identify any suspicious activity or unauthorized configuration changes made by domain administrator accounts, particularly around the time of patch deployment.
