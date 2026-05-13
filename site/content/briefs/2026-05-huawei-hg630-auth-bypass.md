---
title: Huawei HG630 V2 Router Authentication Bypass Vulnerability (CVE-2020-37220)
slug: 2026-05-huawei-hg630-auth-bypass
description: Huawei HG630 V2 router contains an authentication bypass vulnerability (CVE-2020-37220) that allows unauthenticated attackers to obtain administrative access by retrieving the device serial number via the `/api/system/deviceinfo` endpoint and using the last 8 characters as the default password.
date: "2026-05-13T16:18:55Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve
  - authentication-bypass
  - network-device
vendors:
  - Huawei
products:
  - HG630 V2 router
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1592
    technique_name: Gather Victim Host Information
cves:
  - id: CVE-2020-37220
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2020-37220
  - https://www.exploit-db.com/exploits/48310
  - https://www.vulncheck.com/advisories/huawei-hg630-v2-router-authentication-bypass-via-serial-number
  - https://www.youtube.com/watch?v=vOrIL7L_cVc
rules:
  - title: Detect Huawei HG630 V2 Device Info Request
    description: Detects requests to the /api/system/deviceinfo endpoint on Huawei HG630 V2 routers, potentially indicating an attempt to retrieve the serial number for authentication bypass (CVE-2020-37220).
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1592.004
    data_sources:
      - webserver
  - title: Detect Huawei HG630 V2 Successful Admin Login
    description: Detects successful login to Huawei HG630 V2 router web interface after accessing /api/system/deviceinfo. This is based on the assumption the attacker is using the Serial Number.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1110
    data_sources:
      - webserver
rules_count: 2
---

The Huawei HG630 V2 router is vulnerable to an authentication bypass issue (CVE-2020-37220). An unauthenticated attacker can exploit this vulnerability to gain administrative access to the router. By querying the `/api/system/deviceinfo` endpoint, an attacker can retrieve the device's serial number. The last 8 characters of this serial number are then used as the default password for administrative login. This vulnerability allows unauthorized modification of router settings and potential compromise of the network. This issue was reported on May 13, 2026.

## Attack Chain

1. An unauthenticated attacker sends a GET request to the `/api/system/deviceinfo` endpoint on the Huawei HG630 V2 router.
2. The router responds with device information, including the `SerialNumber` field, without requiring authentication.
3. The attacker extracts the `SerialNumber` value from the response.
4. The attacker isolates the last 8 characters of the extracted `SerialNumber`.
5. The attacker attempts to log in to the router's administrative interface via a web browser.
6. The attacker uses "admin" as the username and the last 8 characters of the `SerialNumber` as the password.
7. If the default credentials have not been changed, the attacker successfully authenticates as an administrator.
8. The attacker gains full administrative access to the router and can modify settings, potentially compromising the network.

## Impact

Successful exploitation of CVE-2020-37220 allows an unauthenticated attacker to gain complete administrative control of the Huawei HG630 V2 router. This access enables the attacker to modify router settings, intercept network traffic, conduct man-in-the-middle attacks, or use the compromised device as a pivot point for further attacks within the network. The lack of authentication on a critical endpoint makes this vulnerability particularly severe, potentially impacting a large number of users relying on this router model.

## Recommendation

*   Deploy the Sigma rule `Detect Huawei HG630 V2 Device Info Request` to monitor for suspicious requests to the `/api/system/deviceinfo` endpoint.
*   Deploy the Sigma rule `Detect Huawei HG630 V2 Successful Admin Login` to identify successful logins using credentials derived from the serial number.
*   Apply configuration changes to restrict access to the `/api/system/deviceinfo` endpoint if possible based on the device capabilities.
*   Monitor webserver logs for requests to `/api/system/deviceinfo` and correlate with subsequent login attempts.
