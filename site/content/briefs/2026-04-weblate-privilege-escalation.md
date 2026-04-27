---
title: Weblate Improper Privilege Management via API Endpoint (CVE-2026-34393)
slug: 2026-04-weblate-privilege-escalation
description: Weblate versions prior to 5.17 are vulnerable to improper privilege management due to an API endpoint failing to properly limit the scope of edits, potentially leading to unauthorized modifications.
date: "2026-04-16T12:00:00Z"
severities:
  - high
tags:
  - weblate
  - privilege-escalation
  - web-application
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
cves:
  - id: CVE-2026-34393
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34393
  - https://github.com/WeblateOrg/weblate/pull/18687
  - https://github.com/WeblateOrg/weblate/security/advisories/GHSA-3382-gw9x-477v
rules:
  - title: Weblate Suspicious User Patching API Request
    description: Detects suspicious requests to the Weblate user patching API endpoint that may indicate an attempt to exploit CVE-2026-34393.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Weblate Admin Account Creation via API
    description: Detects attempts to create admin accounts via the Weblate API, which could be indicative of exploitation following privilege escalation.
    platform: sigma
    severity: critical
    tactics:
      - persistence
    techniques:
      - T1098
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Weblate, a web-based localization tool, contains an improper privilege management vulnerability (CVE-2026-34393) affecting versions prior to 5.17. The vulnerability lies in the user patching API endpoint, which doesn't adequately restrict the scope of edits allowed. An attacker with low privileges could potentially exploit this flaw to modify data or settings beyond their authorized permissions. This issue was reported and patched in Weblate version 5.17. Successful exploitation can lead to…
