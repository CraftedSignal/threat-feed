---
title: Authentication Bypass Vulnerability in Schneider Electric PowerChute Serial Shutdown
slug: 2026-09-schneider-powerchute-auth
description: Schneider Electric PowerChute Serial Shutdown version 1.5 and prior contains an improper restriction of excessive authentication attempts vulnerability (CVE-2026-13348) that may allow unauthorized account access via brute-force.
date: "2026-09-17T18:11:06Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:schneider-electric:powerchute_serial_shutdown:*:*:*:*:*:*:*:*
tags:
  - industrial-control-system
  - authentication-bypass
  - cve
vendors:
  - Schneider Electric
products:
  - PowerChute Serial Shutdown (<= 1.5)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110.001
    technique_name: 'Brute Force: Password Guessing'
    evidence: 'CWE-307: Improper Restriction of Excessive Authentication Attempts vulnerability exists that could allow an attacker to gain unauthorized access to a user account by performing an arbitrary number of authentication attempts when redirect handling is disabled.'
    confidence_band: high
cves:
  - id: CVE-2026-13348
    epss: 0.00311
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-260-07
  - https://www.cve.org/CVERecord?id=CVE-2026-13348
  - https://www.se.com/ww/en/download/document/spd-pcss_win_en/
  - https://www.se.com/ww/en/download/document/SPD-PCSS_LNX_EN/
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade PowerChute Serial Shutdown to version 1.6
      owner: IT Operations
      due: 72h
      evidence: Vendor fix provided in the CISA advisory
  mitigation_plan:
    - priority: immediate
      action: Isolate PowerChute management interfaces behind firewalls
      owner: Network Security
      addresses: CVE-2026-13348
      evidence: CISA and Schneider Electric recommended cybersecurity best practices
---

Schneider Electric has identified a vulnerability in its PowerChute Serial Shutdown software, which is used for UPS management and system energy control. The vulnerability, tracked as CVE-2026-13348, is an instance of CWE-307: Improper Restriction of Excessive Authentication Attempts. This flaw exists in versions 1.5 and prior of the application. 

The vulnerability allows an attacker to perform an arbitrary number of authentication attempts against the software when redirect handling is disabled. Because the application fails to adequately throttle or block repeated login requests, it is susceptible to brute-force attacks. Successful exploitation could lead to unauthorized access to a user account, potentially allowing an adversary to manipulate power management settings or disrupt critical system operations. Given that this software often operates in industrial, energy, and IT environments, unauthorized access poses a risk to operational stability.

## Impact

The vulnerability affects users of PowerChute Serial Shutdown across multiple sectors including energy, manufacturing, and commercial facilities worldwide. If exploited, an attacker could gain administrative or user-level access to the application, resulting in the potential disruption of system shutdowns, energy management services, and unauthorized access to system configuration data.

## Recommendation

Prioritize the remediation of CVE-2026-13348 by upgrading all instances of PowerChute Serial Shutdown to version 1.6 or later.

* Upgrade PowerChute Serial Shutdown on all Windows hosts to v1.6 via the official Schneider Electric download portal.
* Upgrade PowerChute Serial Shutdown on all Linux hosts to v1.6 via the official Schneider Electric download portal.
* Ensure that PowerChute management interfaces are isolated from public-facing networks and restricted to trusted administrative segments, as recommended in the Schneider Electric Security Handbook.
* Monitor authentication logs for the PowerChute application for patterns indicative of high-frequency login failures or brute-force activity.
