---
title: AVideo Platform Unauthenticated Live Stream Control via streamerURL Manipulation
slug: 2024-01-avideo-auth-bypass
description: AVideo platform versions up to 26.0 are vulnerable to unauthenticated control of live streams due to manipulation of the `streamerURL` parameter in the `control.json.php` endpoint, enabling actions like dropping publishers or starting/stopping recordings.
date: "2024-01-17T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - avideo
  - authentication-bypass
  - cve-2026-33716
vendors:
  - AVideo
products:
  - AVideo Platform
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33716
rules:
  - title: Detect AVideo streamerURL Authentication Bypass Attempt
    description: Detects attempts to exploit the AVideo streamerURL authentication bypass vulnerability (CVE-2026-33716) by monitoring POST requests to the control.json.php endpoint with a non-empty streamerURL parameter.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1588.006
    data_sources:
      - webserver
      - linux
  - title: Detect AVideo Control Endpoint Access
    description: Detects access to the AVideo control endpoint. Legitimate access should be monitored to create a baseline and identify anomalies more easily.
    platform: sigma
    severity: informational
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

AVideo, an open-source video platform, is vulnerable to an authentication bypass flaw affecting versions up to and including 26.0. The vulnerability resides in the `plugin/Live/standAloneFiles/control.json.php` endpoint, which handles live stream control. By manipulating the `streamerURL` parameter, a malicious actor can redirect token verification requests to a server under their control. This malicious server is designed to always return a positive authentication response (`{"error": false}`), effectively bypassing the intended authentication process. This allows an unauthenticated attacker to take complete control over any live stream hosted on the platform. The vulnerability was patched in commit 388fcd57dbd16f6cb3ebcdf1d08cf2b929941128. This vulnerability poses a severe risk to AVideo platforms as it could lead to unauthorized modification or disruption of live streams.

## Attack Chain

1.  The attacker identifies an AVideo platform running a vulnerable version (<= 26.0).
2.  The attacker crafts a malicious HTTP POST request targeting the `plugin/Live/standAloneFiles/control.json.php` endpoint.
3.  Within the POST request, the attacker includes the `streamerURL` parameter, setting its value to a URL pointing to a server under their control.
4.  The attacker's server is configured to respond to any token verification request with a JSON response: `{"error": false}`.
5.  The AVideo platform, upon receiving the crafted request, sends a token verification request to the attacker-controlled `streamerURL`.
6.  The attacker's server responds with `{"error": false}`, tricking the AVideo platform into believing the user is authenticated.
7.  The attacker can then use other parameters in the `control.json.php` endpoint to perform unauthorized actions on live streams, such as dropping active publishers.
8.  The attacker can also start/stop recordings or probe for the existence of live streams.

## Impact

Successful exploitation of CVE-2026-33716 allows an unauthenticated attacker to gain full control over live streams on the affected AVideo platform. This can lead to various detrimental outcomes, including unauthorized termination of legitimate streams, injection of malicious content into live broadcasts, and disruption of service. The CVSS v3.1 base score for this vulnerability is 9.4, indicating a critical severity level. The number of affected AVideo platforms is unknown, but any instance running a version up to 26.0 is susceptible to this attack.

## Recommendation

*   Apply the patch from commit 388fcd57dbd16f6cb3ebcdf1d08cf2b929941128 to remediate CVE-2026-33716.
*   Deploy the Sigma rule to detect exploitation attempts against the `plugin/Live/standAloneFiles/control.json.php` endpoint.
*   Monitor web server logs for POST requests to `plugin/Live/standAloneFiles/control.json.php` containing the `streamerURL` parameter.
