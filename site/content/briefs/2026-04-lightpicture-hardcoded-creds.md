---
title: osuuu LightPicture Hardcoded Credentials Vulnerability (CVE-2026-6574)
slug: 2026-04-lightpicture-hardcoded-creds
description: CVE-2026-6574 allows remote attackers to manipulate the 'key' argument in the /public/install/lp.sql file via the API Upload Endpoint in osuuu LightPicture <= 1.2.2, leading to hardcoded credentials exposure.
date: "2026-04-19T14:16:11Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve-2026-6574
  - hardcoded-credentials
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-6574
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6574
  - https://vuldb.com/vuln/358209
rules:
  - title: Detect Suspicious LP.SQL Access
    description: Detects attempts to access the lp.sql file, potentially indicating exploitation attempts of CVE-2026-6574.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious Key Argument Manipulation in LP.SQL
    description: Detects suspicious manipulation of the 'key' argument when accessing the lp.sql file, indicating potential exploitation of CVE-2026-6574.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

osuuu LightPicture, up to version 1.2.2, is vulnerable to a hardcoded credentials exposure vulnerability (CVE-2026-6574). This flaw resides within the API Upload Endpoint and is triggered when processing the `/public/install/lp.sql` file. An attacker can manipulate the `key` argument to exploit this vulnerability. The vendor has been notified about the vulnerability but has not responded. Public exploits are available, increasing the risk of exploitation. This vulnerability allows an attacker to potentially gain unauthorized access and control over the application.

## Attack Chain

1.  Attacker identifies an instance of osuuu LightPicture running version 1.2.2 or earlier.
2.  The attacker crafts a malicious HTTP request targeting the API Upload Endpoint.
3.  The request includes a modified `key` argument within the `/public/install/lp.sql` file path.
4.  The application processes the crafted request without proper sanitization.
5.  Due to the manipulated `key` argument, the application exposes hardcoded credentials.
6.  The attacker retrieves the exposed hardcoded credentials from the server's response.
7.  The attacker leverages the acquired credentials to authenticate and gain unauthorized access to the application.
8.  With unauthorized access, the attacker can perform malicious activities such as data theft, modification, or deletion.

## Impact

Successful exploitation of CVE-2026-6574 can lead to complete compromise of the osuuu LightPicture application and potentially the underlying server. The vulnerability exposes hardcoded credentials, enabling attackers to bypass authentication and gain administrative privileges. The impact includes unauthorized access to sensitive data, modification of application settings, and potential disruption of service. The vulnerability affects all installations of osuuu LightPicture up to version 1.2.2.

## Recommendation

*   Deploy the Sigma rule `Detect Suspicious LP.SQL Access` to identify attempts to access the vulnerable file (log source: webserver).
*   Apply input validation and sanitization to the `key` argument within the API Upload Endpoint to prevent manipulation (reference CVE-2026-6574).
*   Monitor web server logs for suspicious requests targeting the `/public/install/lp.sql` file with unusual parameters (log source: webserver).
*   If upgrading is not possible, implement a web application firewall (WAF) rule to block requests containing malicious patterns in the `key` argument (log source: firewall).
