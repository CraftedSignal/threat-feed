---
title: Critical RCE Vulnerability in Cisco Catalyst SD-WAN Controller
slug: 2026-02-cisco-sdwan-rce
description: A critical remote code execution vulnerability exists in Cisco Catalyst SD-WAN Controllers (CVE-2026-20127) due to improper authentication, allowing unauthenticated remote attackers to bypass authentication and gain administrative privileges, potentially leading to network configuration manipulation.
date: "2026-02-27T10:00:00Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - cisco
  - sd-wan
  - rce
  - vulnerability
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
references:
  - https://ccb.belgium.be/advisories/warning-critical-rce-vulnerability-cisco-catalyst-sd-wan-controller-patch-immediately
  - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-rpa-EHchtZk
  - https://www.cyber.gov.au/sites/default/files/2026-02/ACSC-led%20Cisco%20SD-WAN%20Hunt%20Guide.pdf
  - https://blog.talosintelligence.com/uat-8616-sd-wan/
ioc_counts:
  url: 4
rules:
  - title: Detect NETCONF Access from Non-Standard Locations
    description: Detects NETCONF access attempts originating from unusual or unexpected source IP addresses, potentially indicating unauthorized access following exploitation of CVE-2026-20127.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
      - privilege_escalation
    techniques:
      - T1550.002
    data_sources:
      - network_connection
      - linux
  - title: Detect auth.log anomalies
    description: Detects suspicious patterns in the auth.log that could indicate successful or attempted exploitation
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - privilege_escalation
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A critical vulnerability, CVE-2026-20127, affects Cisco Catalyst SD-WAN Controllers. The vulnerability stems from an improper authentication mechanism, which can be exploited by unauthenticated remote attackers. Successful exploitation allows bypassing authentication and gaining administrative privileges. This access could allow the attacker to log in as a high-privileged, non-root user, gaining access to NETCONF, and enabling the manipulation of the SD-WAN fabric's network configuration. The…
