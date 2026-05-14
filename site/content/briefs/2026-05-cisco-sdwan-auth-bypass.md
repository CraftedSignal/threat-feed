---
title: Cisco Catalyst SD-WAN Controller Authentication Bypass Vulnerability
slug: 2026-05-cisco-sdwan-auth-bypass
description: A vulnerability in the peering authentication of Cisco Catalyst SD-WAN Controller and Manager (CVE-2026-20182) could allow a remote, unauthenticated attacker to bypass authentication and obtain administrative privileges by sending crafted requests.
date: "2026-05-14T16:01:09Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - authentication bypass
  - privilege escalation
  - cisco
  - sd-wan
vendors:
  - Cisco
products:
  - Catalyst SD-WAN Controller
  - Catalyst SD-WAN Manager
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
references:
  - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-rpa2-v69WY2SW
  - https://www.cisco.com/c/en/us/support/docs/routers/sd-wan/225842-remediate-catalyst-sd-wan-security.html
rules:
  - title: Detect CVE-2026-20182 Exploitation Attempt - Crafted Peering Request
    description: Detects CVE-2026-20182 exploitation attempt - suspicious patterns indicative of crafted requests to bypass peering authentication in Cisco SD-WAN Controllers.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - privilege_escalation
    techniques:
      - T1190
      - T1555
    data_sources:
      - network_connection
      - cisco
  - title: Detect CVE-2026-20182 Exploitation - Unauthorized NETCONF Session
    description: Detects CVE-2026-20182 exploitation - monitoring for successful, but unauthorized, NETCONF sessions that could stem from an authentication bypass.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - network_connection
      - cisco
rules_count: 2
---

A critical vulnerability exists in the peering authentication mechanism of Cisco Catalyst SD-WAN Controller (formerly SD-WAN vSmart) and Cisco Catalyst SD-WAN Manager (formerly SD-WAN vManage). Disclosed in May 2026 as a follow-up to an earlier advisory in February 2026, this flaw allows an unauthenticated, remote attacker to bypass authentication and gain administrative privileges on affected systems. The vulnerability resides within the control connection handshaking process. Successful exploitation grants the attacker access to NETCONF, enabling them to manipulate network configurations within the SD-WAN fabric. This bypass is particularly concerning as it does not require valid credentials, posing a severe risk to the confidentiality, integrity, and availability of the SD-WAN infrastructure. The vulnerability is identified as CVE-2026-20182.

## Attack Chain

1. The attacker sends a crafted request to a vulnerable Cisco Catalyst SD-WAN Controller or Manager.
2. The crafted request exploits a flaw in the peering authentication mechanism during control connection handshaking.
3. The system incorrectly authenticates the attacker, bypassing normal authentication procedures.
4. The attacker gains access to the system as an internal, high-privileged, non-root user account.
5. The attacker leverages the compromised account to access NETCONF (Network Configuration Protocol).
6. Through NETCONF, the attacker manipulates the network configuration of the SD-WAN fabric.
7. The attacker modifies routing policies, access control lists, or other critical network settings.
8. The attacker disrupts network operations, intercepts traffic, or performs other malicious actions within the SD-WAN environment.

## Impact

Successful exploitation of this vulnerability (CVE-2026-20182) allows an unauthenticated attacker to gain full control over the SD-WAN fabric. This could lead to widespread network disruption, data breaches, and the potential for long-term compromise of sensitive data. Given the central role of SD-WAN in managing network traffic across geographically dispersed locations, a successful attack could have significant consequences for organizations relying on Cisco Catalyst SD-WAN solutions. The advisory recommends collecting admin-tech data before upgrading to preserve possible indicators of compromise, highlighting the potential for widespread exploitation.

## Recommendation

*   Immediately apply the software updates released by Cisco to address CVE-2026-20182 on all affected Cisco Catalyst SD-WAN Controller and Manager instances.
*   Prior to upgrading, follow Cisco's guidance to issue the `request admin-tech` command on all control components to collect potential indicators of compromise, as mentioned in the [Cisco Security Advisory](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-rpa2-v69WY2SW).
*   Monitor network traffic for suspicious activity indicative of unauthorized NETCONF access, which could be a sign of exploitation as described in the [Overview](#overview).
*   Deploy the Sigma rules provided below to detect potential exploitation attempts against Cisco Catalyst SD-WAN Controllers, focusing on crafted requests and unauthorized access.
