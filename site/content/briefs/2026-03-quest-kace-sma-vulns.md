---
title: Critical Vulnerabilities in Quest KACE SMA Allow System Takeover
slug: 2026-03-quest-kace-sma-vulns
description: Multiple critical vulnerabilities in Quest KACE Systems Management Appliance (SMA), including authentication bypass and 2FA bypass, allow unauthenticated attackers to achieve system takeover and cause denial of service; active exploitation is reported.
date: "2026-03-21T12:00:00Z"
severities:
  - critical
tags:
  - quest-kace
  - vulnerability
  - authentication-bypass
  - 2fa-bypass
  - denial-of-service
  - sma
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
  - tactic_id: TA0006
    tactic_name: Defense Evasion
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://ccb.belgium.be/advisories/warning-critical-vulnerabilities-found-quest-kace-systems-management-appliance-patch
  - https://support.quest.com/kb/4379499/quest-response-to-kace-sma-vulnerabilities-cve-2025-32975-cve-2025-32976-cve-2025-32977-cve-2025-32978
  - https://seclists.org/fulldisclosure/2025/Jun/22
  - https://seclists.org/fulldisclosure/2025/Jun/23
  - https://seclists.org/fulldisclosure/2025/Jun/24
  - https://seclists.org/fulldisclosure/2025/Jun/25
  - https://arcticwolf.com/resources/blog/cve-2025-32975/
rules:
  - title: Detect Unauthenticated Access Attempts to KACE SMA
    description: Detects potential unauthenticated access attempts to KACE SMA by monitoring for specific HTTP requests that are typically associated with authenticated sessions.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - web
      - kace_sma
  - title: Detect Suspicious File Uploads to KACE SMA
    description: Detects suspicious file uploads to the KACE SMA server, potentially indicating an attempt to exploit CVE-2025-32977.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - web
      - kace_sma
rules_count: 2
---

Quest KACE Systems Management Appliance (SMA) is an IT systems management solution used by organizations to manage and secure endpoints. In June 2025, multiple critical vulnerabilities were disclosed. These include CVE-2025-32975, an authentication bypass; CVE-2025-32976, a 2FA bypass; CVE-2025-32977, malicious backup upload; and CVE-2025-32978, license replacement leading to denial of service. The vulnerabilities were discovered during a third-party assessment. As of March 20, 2026, active…
