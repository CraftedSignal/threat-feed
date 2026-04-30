---
title: Gematik Authenticator Authentication Flow Hijacking Vulnerability (CVE-2026-33875)
slug: 2026-03-gematik-auth-hijack
description: Gematik Authenticator versions prior to 4.16.0 are vulnerable to authentication flow hijacking via malicious deep links, potentially allowing attackers to authenticate with victim user identities.
date: "2026-03-27T21:17:24Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - cve-2026-33875
  - authentication-hijacking
  - gematik-authenticator
  - deeplink
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33875
  - https://github.com/gematik/app-Authenticator/security/advisories/GHSA-qg87-cf56-2rmr
rules:
  - title: Detect Gematik Authenticator Deep Link Hijacking Attempt
    description: Detects suspicious process execution originating from Gematik Authenticator potentially related to deep link hijacking attempts.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
      - T1566.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious Network Connection from Gematik Authenticator After Deep Link
    description: Detects suspicious outbound network connections initiated by Gematik Authenticator after a deeplink execution.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

The Gematik Authenticator, designed for secure user authentication to digital health applications, has a critical vulnerability affecting versions prior to 4.16.0. This vulnerability, identified as CVE-2026-33875, allows for authentication flow hijacking. An attacker can exploit this by crafting a malicious deep link. If a user clicks on this link, the attacker can potentially authenticate using the identity of the victim. This poses a significant risk to user privacy and data security within…
