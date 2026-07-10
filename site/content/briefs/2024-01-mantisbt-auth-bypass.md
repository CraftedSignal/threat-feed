---
title: MantisBT Authentication Bypass via SOAP API on MySQL
slug: 2024-01-mantisbt-auth-bypass
description: MantisBT instances running on MySQL are vulnerable to an authentication bypass in the SOAP API due to improper type checking on the password parameter, allowing attackers with a valid username to log in without the actual password.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - mantisbt
  - authentication-bypass
  - soap-api
vendors:
  - MantisBT
products:
  - MantisBT
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-phrq-pc6r-f6gh
  - https://mantisbt.org/bugs/view.php?id=36902
  - https://mantisbt.org/docs/master/en-US/Admin_Guide/html-desktop/#admin.config.api.disable
rules:
  - title: Detect MantisBT SOAP API Authentication Bypass Attempt
    description: Detects suspicious SOAP requests to MantisBT that may indicate an authentication bypass attempt.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detecting MantisBT SOAP API Disabled Message
    description: Detects when MantisBT returns a message indicating the SOAP API is disabled.
    platform: sigma
    severity: informational
    tactics:
      - defense_evasion
    data_sources:
      - webserver
      - linux
  - title: MantisBT SOAP API Username Retrieval
    description: Detects attempts to retrieve user information from the MantisBT SOAP API which is possible even when disabled.
    platform: sigma
    severity: low
    tactics:
      - reconnaissance
    techniques:
      - T1595
    data_sources:
      - webserver
      - linux
rules_count: 3
---

MantisBT, a widely used web-based bug tracking system, is susceptible to a critical authentication bypass vulnerability (CVE-2026-30849) affecting instances utilizing MySQL or compatible databases. This flaw stems from inadequate type checking on the password parameter within the SOAP API. Specifically, the vulnerability exists in MantisBT versions prior to 2.28.1. An attacker who knows a valid username can exploit this weakness to gain unauthorized access to the SOAP API, circumventing the need for the correct password. Other database backends are not affected due to their stricter type handling. Successful exploitation grants the attacker the ability to execute any API function accessible to the compromised user, posing a significant risk of data breaches, system compromise, and unauthorized modifications.

## Attack Chain

1.  Attacker identifies a vulnerable MantisBT instance running on MySQL or a compatible database.
2.  Attacker obtains a valid username for the MantisBT instance (e.g., through OSINT or social engineering).
3.  Attacker crafts a malicious SOAP envelope containing the target username and a manipulated password parameter designed to exploit the type checking vulnerability.
4.  Attacker sends the crafted SOAP request to the MantisBT instance's SOAP API endpoint.
5.  The vulnerable MantisBT instance improperly processes the password parameter due to insufficient type validation.
6.  The MantisBT instance authenticates the attacker as the targeted user without requiring the correct password.
7.  Attacker leverages the authenticated SOAP API session to execute privileged API functions.
8.  Attacker exfiltrates sensitive bug data, modifies bug reports, or performs other malicious actions within the MantisBT system.

## Impact

Successful exploitation of this vulnerability allows an attacker to bypass authentication and gain unauthorized access to a MantisBT instance. The impact includes potential data breaches involving sensitive bug reports, project information, and user data. Attackers can modify or delete bug reports, disrupt project workflows, or escalate their access to other systems connected to the MantisBT instance. While the exact number of affected MantisBT installations is unknown, the widespread use of MantisBT across various sectors suggests a potentially broad impact. Disabling the SOAP API mitigates the risk, but still allows the attacker to retrieve user account information including email address and real name.

## Recommendation

*   Upgrade MantisBT to version 2.28.1 or later to patch CVE-2026-30849 and remediate the authentication bypass vulnerability.
*   If upgrading is not immediately feasible, disable the SOAP API as a workaround, referencing the [MantisBT documentation](https://mantisbt.org/docs/master/en-US/Admin_Guide/html-desktop/#admin.config.api.disable) .
*   Monitor web server logs for suspicious SOAP API requests containing unusual password parameters indicative of exploitation attempts. Deploy a webserver rule to detect unusual password parameters in SOAP API requests.
