---
title: Payload CMS Password Reset Vulnerability (CVE-2026-34751)
slug: 2026-04-payload-cms-reset-vuln
description: An unauthenticated attacker can perform actions on behalf of a user initiating a password reset in Payload CMS versions prior to 3.79.1 due to a flaw in the password recovery flow, potentially leading to account takeover or privilege escalation.
date: "2026-04-01T18:16:31Z"
severities:
  - critical
tags:
  - cve-2026-34751
  - payload-cms
  - password-reset
  - vulnerability
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1199
    technique_name: Bypass Password Reset
cves:
  - id: CVE-2026-34751
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34751
  - https://github.com/payloadcms/payload/releases/tag/v3.79.1
  - https://github.com/payloadcms/payload/security/advisories/GHSA-hp5w-3hxx-vmwf
ioc_counts:
  email: 1
rules:
  - title: Detect Payload CMS Password Reset Abuse
    description: Detects potential abuse of the Payload CMS password reset functionality by monitoring for unusual patterns of password reset requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1078
      - T1078.004
    data_sources:
      - webserver
      - linux
  - title: Detect Payload CMS Password Change Attempt from Unusual Source
    description: Detects password change attempts from IP addresses that have not previously authenticated.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1078
      - T1078.004
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Payload CMS is a free and open-source headless content management system. Prior to version 3.79.1, a critical vulnerability (CVE-2026-34751) exists in the `@payloadcms/graphql` and `payload` components concerning the password recovery flow. This flaw allows an unauthenticated attacker to potentially perform actions as a legitimate user who has initiated a password reset process. The vulnerability arises from improper handling of password reset tokens or insufficient validation during the…
