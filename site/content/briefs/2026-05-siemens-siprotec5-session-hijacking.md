---
title: Siemens SIPROTEC 5 Insufficient Session ID Randomness Leads to Session Hijacking (CVE-2024-54017)
slug: 2026-05-siemens-siprotec5-session-hijacking
description: Siemens SIPROTEC 5 devices are vulnerable to session hijacking (CVE-2024-54017) due to the use of insufficiently random numbers in session identifier generation, potentially allowing an unauthenticated remote attacker to brute-force a valid session and gain unauthorized read access.
date: "2026-05-14T15:08:07Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - ics
  - session hijacking
  - cve-2024-54017
  - siemens
  - critical infrastructure
vendors:
  - Siemens
products:
  - SIPROTEC 5 6MD84 (CP300)
  - SIPROTEC 5 6MD85 (CP200)
  - SIPROTEC 5 6MD85 (CP300)
  - SIPROTEC 5 6MD86 (CP200)
  - SIPROTEC 5 6MD86 (CP300)
  - SIPROTEC 5 6MD89 (CP300)
  - SIPROTEC 5 6MU85 (CP300)
  - SIPROTEC 5 7KE85 (CP200)
  - SIPROTEC 5 7KE85 (CP300)
  - SIPROTEC 5 7SA82 (CP100)
  - SIPROTEC 5 7SA82 (CP150)
  - SIPROTEC 5 7SA84 (CP200)
  - SIPROTEC 5 7SA86 (CP200)
  - SIPROTEC 5 7SA86 (CP300)
  - SIPROTEC 5 7SA87 (CP200)
  - SIPROTEC 5 7SA87 (CP300)
  - SIPROTEC 5 7SD82 (CP100)
  - SIPROTEC 5 7SD82 (CP150)
  - SIPROTEC 5 7SD84 (CP200)
  - SIPROTEC 5 7SD86 (CP200)
  - SIPROTEC 5 7SD86 (CP300)
  - SIPROTEC 5 7SD87 (CP200)
  - SIPROTEC 5 7SD87 (CP300)
  - SIPROTEC 5 7SJ81 (CP100)
  - SIPROTEC 5 7SJ81 (CP150)
  - SIPROTEC 5 7SJ82 (CP100)
  - SIPROTEC 5 7SJ82 (CP150)
  - SIPROTEC 5 7SJ85 (CP200)
  - SIPROTEC 5 7SJ85 (CP300)
  - SIPROTEC 5 7SJ86 (CP200)
  - SIPROTEC 5 7SJ86 (CP300)
  - SIPROTEC 5 7SK82 (CP100)
  - SIPROTEC 5 7SK82 (CP150)
  - SIPROTEC 5 7SK85 (CP200)
  - SIPROTEC 5 7SK85 (CP300)
  - SIPROTEC 5 7SL82 (CP100)
  - SIPROTEC 5 7SL82 (CP150)
  - SIPROTEC 5 7SL86 (CP200)
  - SIPROTEC 5 7SL86 (CP300)
  - SIPROTEC 5 7SL87 (CP200)
  - SIPROTEC 5 7SL87 (CP300)
  - SIPROTEC 5 7SS85 (CP200)
  - SIPROTEC 5 7SS85 (CP300)
  - SIPROTEC 5 7ST85 (CP200)
  - SIPROTEC 5 7ST85 (CP300)
  - SIPROTEC 5 7ST86 (CP300)
  - SIPROTEC 5 7SX82 (CP150)
  - SIPROTEC 5 7SX85 (CP300)
  - SIPROTEC 5 7SY82 (CP150)
  - SIPROTEC 5 7UM85 (CP300)
  - SIPROTEC 5 7UT82 (CP100)
  - SIPROTEC 5 7UT82 (CP150)
  - SIPROTEC 5 7UT85 (CP200)
  - SIPROTEC 5 7UT85 (CP300)
  - SIPROTEC 5 7UT86 (CP200)
  - SIPROTEC 5 7UT86 (CP300)
  - SIPROTEC 5 7UT87 (CP200)
  - SIPROTEC 5 7UT87 (CP300)
  - SIPROTEC 5 7VE85 (CP300)
  - SIPROTEC 5 7VK87 (CP200)
  - SIPROTEC 5 7VK87 (CP300)
  - SIPROTEC 5 7VU85 (CP300)
  - SIPROTEC 5 Compact 7SX800 (CP050)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1185
    technique_name: Brute Force
cves:
  - id: CVE-2024-54017
    cvss: 5.3
    epss: 0.00029
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-13
  - https://github.com/cisagov/CSAF/blob/develop/csaf_files/OT/white/2026/icsa-26-134-13.json
  - https://www.cve.org/CVERecord?id=CVE-2024-54017
  - https://support.industry.siemens.com/cs/ww/en/view/109814150/
  - https://support.industry.siemens.com/cs/ww/en/view/109757433/
  - https://support.industry.siemens.com/cs/ww/en/view/109796884/
rules:
  - title: Detect CVE-2024-54017 Exploitation Attempts - Multiple Unique Session IDs
    description: Detects CVE-2024-54017 exploitation attempts by monitoring web server logs for a high number of unique session IDs originating from the same source IP address within a short time frame, indicating potential brute-force activity.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1595
      - T1595.002
    data_sources:
      - webserver
  - title: Detect CVE-2024-54017 Exploitation Attempts - Invalid Session ID Responses
    description: Detects CVE-2024-54017 exploitation attempts by monitoring web server logs for a series of failed requests (e.g., HTTP 401, 403) after initial requests with a different session ID, indicating brute-forcing attempts.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1595
      - T1595.002
    data_sources:
      - webserver
rules_count: 2
---

Multiple Siemens SIPROTEC 5 devices are affected by a vulnerability (CVE-2024-54017) stemming from the use of insufficiently random numbers in generating session identifiers. This weakness could be exploited by an unauthenticated remote attacker to conduct a brute-force attack against a valid session identifier. Successful exploitation grants the attacker unauthorized read access to limited information from the web server. The affected products include a range of SIPROTEC 5 devices, specifically versions below V11.0 for certain models. Siemens is preparing fixes and recommends countermeasures where fixes are not yet available. This vulnerability impacts critical infrastructure sectors, particularly critical manufacturing, where these devices are deployed worldwide.

## Attack Chain

1.  An unauthenticated attacker identifies a vulnerable SIPROTEC 5 device exposed on a network.
2.  The attacker sends an initial HTTP request to the device's web server to initiate a session.
3.  The device generates a session identifier based on an insufficiently random number generator.
4.  The attacker begins a brute-force attack, attempting different session identifier values.
5.  The attacker sends subsequent HTTP requests with each guessed session identifier.
6.  If a guessed session identifier matches a valid active session, the device grants the attacker access.
7.  The attacker gains unauthorized read access to limited information from the web server.
8.  The attacker may be able to glean sensitive configuration details or operational data.

## Impact

Successful exploitation of CVE-2024-54017 could allow an unauthenticated attacker to gain unauthorized read access to sensitive information from vulnerable Siemens SIPROTEC 5 devices. The impact is limited to read access, but exposed configuration data or operational parameters could provide valuable information to an attacker for further malicious activity. The vulnerability affects a wide range of SIPROTEC 5 devices deployed globally, particularly in critical manufacturing sectors.

## Recommendation

*   Apply available updates to V11.0 or later versions for affected SIPROTEC 5 devices as provided by Siemens to remediate CVE-2024-54017.
*   Monitor web server logs for unusual patterns of requests with different session identifiers, indicative of brute-force attempts targeting CVE-2024-54017. Use the provided Sigma rule to detect these patterns.
*   Implement network segmentation and firewalls to restrict access to SIPROTEC 5 devices and minimize network exposure, as mentioned in the CISA advisory.
