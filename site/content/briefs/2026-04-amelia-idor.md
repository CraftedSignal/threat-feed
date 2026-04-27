---
title: Amelia WordPress Plugin IDOR Vulnerability CVE-2026-5465
slug: 2026-04-amelia-idor
description: The Amelia WordPress plugin is vulnerable to an insecure direct object reference, allowing authenticated attackers with Provider-level access or higher to escalate privileges and gain persistence by taking over any WordPress account, including Administrator by manipulating the `externalId` field.
date: "2026-04-07T07:16:24Z"
severities:
  - critical
tags:
  - wordpress
  - amelia
  - idor
  - privilege-escalation
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-5465
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5465
rules:
  - title: Detect Amelia Plugin IDOR Attack
    description: Detects attempts to exploit the IDOR vulnerability (CVE-2026-5465) in the Amelia WordPress plugin by monitoring for suspicious POST requests with modified externalId parameters.
    platform: sigma
    severity: critical
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Amelia wp_set_password usage with suspicious externalID
    description: Detects potentially malicious use of wp_set_password function within the Amelia Plugin by non-admin users.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Amelia WordPress plugin, specifically the "Booking for Appointments and Events Calendar", contains an Insecure Direct Object Reference (IDOR) vulnerability (CVE-2026-5465) in versions up to and including 2.1.3. This flaw resides within the `UpdateProviderCommandHandler` and stems from insufficient validation when a Provider (Employee) user modifies their profile. The critical issue is the ability to manipulate the `externalId` field, which directly corresponds to a WordPress user ID. By…
