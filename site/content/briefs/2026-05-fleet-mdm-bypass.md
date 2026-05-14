---
title: Fleet Windows MDM Management Endpoint Authentication Bypass Vulnerability
slug: 2026-05-fleet-mdm-bypass
description: CVE-2026-23998 describes a vulnerability in Fleet's Windows MDM management endpoint that allows requests to be processed without proper client certificate validation, potentially allowing an attacker to impersonate a device and retrieve sensitive configuration data.
date: "2026-05-14T13:15:45Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - authentication-bypass
  - credential-access
  - mdm
vendors:
  - FleetDM
products:
  - fleet
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials in Files
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1555
    technique_name: Credentials in Files
references:
  - https://github.com/advisories/GHSA-2rc4-7jc6-qffh
  - CVE-2026-23998
iocs:
  - type: email
    value: security@fleetdm.com
ioc_counts:
  email: 1
rules:
  - title: Detect CVE-2026-23998 Exploitation Attempt — Missing Client Certificate
    description: Detects CVE-2026-23998 exploitation attempt — HTTP request to Windows MDM endpoint without client certificate indicating potential authentication bypass.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - defense_evasion
    techniques:
      - T1555
    data_sources:
      - webserver
  - title: Detect CVE-2026-23998 Potential Exploitation — High Volume of Requests to MDM Endpoint from Single Source Without Client Certificates
    description: Detects CVE-2026-23998 potential exploitation — High volume of requests to Windows MDM endpoint from a single source without client certificate indicating potential brute force attempt or automated exploitation.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - defense_evasion
    techniques:
      - T1555
    data_sources:
      - webserver
rules_count: 2
---

Fleet's Windows MDM management endpoint is vulnerable to an authentication bypass (CVE-2026-23998) due to improper client certificate validation. Specifically, requests to the MDM endpoint could be processed even without a valid client certificate. An attacker with prior knowledge of a valid enrolled device identifier could exploit this vulnerability to impersonate that device. Successful exploitation could allow the attacker to receive sensitive configuration payloads intended for the targeted device. This vulnerability affects Fleet versions prior to 4.81.0. It's important for defenders to identify and mitigate this risk to protect sensitive device configurations and data.

## Attack Chain

1.  Attacker identifies a target Windows device enrolled in Fleet MDM and obtains its device identifier.
2.  Attacker crafts a malicious HTTP request to the Fleet Windows MDM management endpoint.
3.  The malicious request is sent without a valid client certificate.
4.  Due to the vulnerability, the Fleet server incorrectly processes the request as if it were authenticated.
5.  The Fleet server retrieves the configuration payload associated with the target device identifier.
6.  The configuration payload, potentially containing sensitive information (Wi-Fi passwords, VPN configurations, certificates), is sent to the attacker.
7.  Attacker gains unauthorized access to sensitive configuration data of the targeted Windows device.

## Impact

Successful exploitation of CVE-2026-23998 allows an attacker to retrieve sensitive configuration data intended for a specific Windows device managed by Fleet MDM. This could include Wi-Fi passwords, VPN configurations, certificates, and other secrets delivered through MDM profiles. The vulnerability does not allow the attacker to enroll new devices, gain administrative access to Fleet, or compromise the Fleet control plane. The impact is limited to the targeted Windows device, but exfiltration of sensitive information from that device could lead to broader network compromise.

## Recommendation

*   Upgrade Fleet to version 4.81.0 or later to patch CVE-2026-23998 (reference: Affected Packages).
*   If an immediate upgrade is not possible, temporarily disable Windows MDM (reference: Workarounds).
*   Monitor webserver logs for requests to the MDM endpoint lacking client certificates, using the provided Sigma rules (reference: rules).
