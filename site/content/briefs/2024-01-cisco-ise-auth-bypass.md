---
title: Cisco Identity Services Engine Authentication Bypass Vulnerabilities
slug: 2024-01-cisco-ise-auth-bypass
description: Multiple vulnerabilities in Cisco Identity Services Engine (ISE) could allow a remote attacker to bypass authorization mechanisms or examine error messages to gain access to sensitive information.
date: "2026-05-06T16:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cisco
  - authentication-bypass
  - vulnerability
vendors:
  - Cisco
products:
  - Identity Services Engine
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Information Stores
references:
  - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-unauth-bypass-uxjRXGpb
rules:
  - title: Detect Cisco ISE Unauthorized Access Attempt via Web Request
    description: Detects suspicious web requests to Cisco ISE that may indicate an attempt to bypass authentication.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
  - title: Detect Cisco ISE Error Message Information Leakage
    description: Detects web server logs showing error messages from Cisco ISE that contain sensitive information.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Cisco Identity Services Engine (ISE) is affected by multiple vulnerabilities that could lead to unauthorized access and information disclosure. These vulnerabilities, identified as CVE-2026-20193 and CVE-2026-20195, can be exploited by a remote attacker to bypass authorization controls or to glean sensitive data from error messages. Successful exploitation could compromise the confidentiality and integrity of the affected Cisco ISE deployment. Cisco has released software updates to address these issues; there are no known workarounds.

## Attack Chain

1.  Attacker identifies a vulnerable Cisco ISE instance exposed to the network.
2.  The attacker sends a crafted request designed to exploit CVE-2026-20193, aiming to bypass authentication.
3.  Due to insufficient authorization checks, the attacker gains unauthorized access to certain features or data within ISE.
4.  Alternatively, the attacker sends specific requests crafted to trigger verbose error messages related to CVE-2026-20195.
5.  The attacker parses the error messages, extracting sensitive information such as configuration details or internal system data.
6.  The attacker uses the acquired information to further compromise the ISE system or gain access to connected network resources.

## Impact

Successful exploitation of these vulnerabilities could allow unauthorized access to the Cisco ISE, potentially exposing sensitive configuration data and network access policies. While the advisory does not specify the number of affected customers, a successful attack could enable an attacker to move laterally within the network or disrupt network services.

## Recommendation

*   Apply the latest software updates provided by Cisco to address CVE-2026-20193 and CVE-2026-20195 on all affected Cisco Identity Services Engine (ISE) instances.
*   Monitor network traffic for suspicious requests targeting Cisco ISE instances that may indicate exploitation attempts.
