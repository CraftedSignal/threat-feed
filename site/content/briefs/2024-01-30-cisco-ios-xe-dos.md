---
title: Cisco IOS and IOS XE HTTP Server Denial-of-Service Vulnerability (CVE-2026-20125)
slug: 2024-01-30-cisco-ios-xe-dos
description: CVE-2026-20125 allows an authenticated, remote attacker to cause a denial of service by sending malformed HTTP requests to a Cisco IOS or IOS XE device, triggering a device reload.
date: "2024-01-30T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cisco
  - ios
  - ios-xe
  - dos
  - CVE-2026-20125
vendors:
  - Cisco
products:
  - Cisco IOS
  - Cisco IOS XE
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-20125
rules:
  - title: Detect Malformed HTTP Requests to Cisco Devices
    description: Detects malformed HTTP requests potentially targeting Cisco devices by looking for unusual characters or patterns in the request URI.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - webserver
      - linux
  - title: Cisco Device Reload Detection
    description: Detects unexpected Cisco device reloads by monitoring system logs for reload messages. May require correlation with other network events to reduce false positives.
    platform: sigma
    severity: low
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - firewall
      - cisco
  - title: Detect HTTP 400 Responses from Cisco Devices
    description: Detects HTTP 400 Bad Request responses originating from Cisco devices, which may indicate exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - webserver
      - linux
rules_count: 3
---

Cisco IOS and IOS XE Software are vulnerable to a denial-of-service condition due to improper validation of user-supplied input within the HTTP Server feature. This vulnerability, identified as CVE-2026-20125, affects devices running specific releases of Cisco IOS Software and Cisco IOS XE Software. An authenticated, remote attacker can exploit this vulnerability by sending malformed HTTP requests to a vulnerable device. Successful exploitation leads to a watchdog timer expiration, causing the device to reload unexpectedly. To exploit this vulnerability, the attacker must possess a valid user account on the targeted Cisco device. This issue was reported on 2026-03-25.

## Attack Chain

1. An attacker obtains valid user credentials for a Cisco IOS or IOS XE device. This could be achieved through social engineering, credential stuffing, or other means.
2. The attacker establishes a connection to the HTTP Server feature on the targeted device via HTTP or HTTPS.
3. The attacker crafts a series of malformed HTTP requests designed to exploit the input validation vulnerability.
4. These malformed requests are sent to the device. The specific nature of the malformed requests is not detailed in the source but could involve exceeding expected input lengths, using unexpected characters, or other forms of invalid data.
5. Due to the lack of proper input validation, the device processes the malformed requests, leading to an internal error.
6. The error causes the watchdog timer on the device to expire.
7. Upon watchdog timer expiration, the device initiates a reload sequence.
8. The device reloads, resulting in a denial-of-service condition for legitimate users.

## Impact

Successful exploitation of CVE-2026-20125 results in a denial-of-service condition, rendering the affected Cisco device unavailable. The scope of the impact depends on the role of the device within the network. If the device is a critical router or switch, the outage could disrupt network connectivity for a large number of users or services. The severity of the impact also depends on how quickly the device can be restored to normal operation. The vulnerability requires an authenticated attacker, limiting the scope of potential attackers.

## Recommendation

*   Apply the appropriate patch or upgrade to a version of Cisco IOS or IOS XE Software that resolves CVE-2026-20125. Refer to the Cisco advisory for specific details on affected versions and recommended fixes.
*   Monitor network traffic for suspicious HTTP requests targeting Cisco IOS or IOS XE devices (see the "Detect Malformed HTTP Requests to Cisco Devices" Sigma rule).
*   Implement strong password policies and multi-factor authentication to reduce the risk of unauthorized access to Cisco devices, as exploitation requires a valid user account.
*   Review logs for unexpected device reloads, which could be indicative of successful exploitation (see the "Cisco Device Reload Detection" Sigma rule).
