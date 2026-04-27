---
title: Critical Certificate Validation Vulnerability in CISCO Webex Allows User Impersonation
slug: 2026-04-cisco-webex-cert-bypass
description: A critical improper certificate validation vulnerability in CISCO Webex versions 39.6 - 45.4 (CVE-2026-20184) allows a remote, unprivileged attacker to impersonate users, gain unauthorized access, and join meetings without authorization, potentially impacting confidentiality, integrity, and availability.
date: "2026-04-17T09:19:48Z"
severities:
  - critical
tags:
  - cisco
  - webex
  - sso
  - certificate-validation
  - user-impersonation
  - cve-2026-20184
  - cloud
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
cves:
  - id: CVE-2026-20184
    cvss: 9.8
    epss: 0.00051
references:
  - https://ccb.belgium.be/advisories/warning-critical-improper-certificate-validation-cisco-webex-can-lead-user-impersonation
  - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-webex-cui-cert-8jSZYhWL
  - https://nvd.nist.gov/vuln/detail/CVE-2026-20184
rules:
  - title: Webex Suspicious Authentication Pattern
    description: Detects suspicious authentication attempts to Webex that may indicate exploitation of CVE-2026-20184
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1550.002
    data_sources:
      - webserver
      - linux
  - title: Webex Unauthorized Meeting Join Attempt
    description: Detects attempts to join Webex meetings without proper authorization following CVE-2026-20184 exploitation
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1078
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical vulnerability, CVE-2026-20184, has been identified in the Single Sign-On (SSO) implementation with Control Hub in CISCO Webex versions 39.6 through 45.4. This improper certificate validation issue allows an unauthenticated, remote attacker to bypass security controls and impersonate legitimate users. CISCO Webex is a widely used cloud-based platform for video meetings and collaboration. Successful exploitation could lead to unauthorized access to sensitive information, disruption of…
