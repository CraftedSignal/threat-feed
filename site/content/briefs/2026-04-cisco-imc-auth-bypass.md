---
title: Critical Authentication Bypass Vulnerability in Cisco Integrated Management Controller (CVE-2026-20093)
slug: 2026-04-cisco-imc-auth-bypass
description: An unauthenticated remote attacker can exploit CVE-2026-20093 to bypass authentication in Cisco Integrated Management Controller (IMC), gain full administrative access, and manipulate hardware settings, potentially disrupting critical infrastructure.
date: "2026-04-03T14:00:09Z"
severities:
  - critical
tags:
  - authentication bypass
  - cisco
  - imc
  - cve-2026-20093
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0006
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0006
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials from Password Stores
cves:
  - id: CVE-2026-20093
    cvss: 9.8
    epss: 0.00031
references:
  - https://ccb.belgium.be/advisories/warning-critical-authentication-bypass-vulnerability-cisco-integrated-management
  - https://www.cisco.com
  - https://nvd.nist.gov
rules:
  - title: Detect Cisco IMC Authentication Bypass Attempt via HTTP Request
    description: Detects attempts to exploit the Cisco IMC authentication bypass vulnerability (CVE-2026-20093) by monitoring suspicious HTTP requests.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Cisco IMC Administrative Access After Potential Authentication Bypass
    description: Detects potential administrative access to Cisco IMC after a possible authentication bypass, by monitoring for administrative-level actions.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Cisco IMC Password Change Activity
    description: Detects password change activity through the webserver logs that might indicate an attacker changing user credentials.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
rules_count: 3
---

A critical authentication bypass vulnerability, CVE-2026-20093, affects multiple versions of Cisco Integrated Management Controller (IMC) software. The vulnerability allows an unauthenticated remote attacker to bypass the login process and gain full administrative privileges on the affected system. This flaw stems from improper input validation (CWE-20). Exploitation grants the attacker the ability to change user passwords, manipulate hardware settings such as power cycling servers, and…
