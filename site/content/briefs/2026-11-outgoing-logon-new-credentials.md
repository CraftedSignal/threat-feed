---
brief_id: brief-2026-11-11-outgoing-logon-new-credentials
event_id: brief-2026-11-11-outgoing-logon-new-credentials
revision: 1
activity_at: "2026-11-11T09:23:57Z"
title: 'Windows Security: Detecting Logon Type 9'
slug: 2026-11-outgoing-logon-new-credentials
description: This detection identifies Windows logon events of type 9, which specify new credentials.
date: "2026-11-11T09:23:57Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
tags:
  - lateral-movement
  - windows
  - security-monitoring
references:
  - https://web.archive.org/web/20250329181845/https://go.recordedfuture.com/hubfs/reports/mtp-2021-0914.pdf
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/account_management/win_security_susp_logon_newcredentials.yml
rules:
  - title: Detect Outgoing Logon with New Credentials (Logon Type 9)
    description: Detects Windows logon events of type 9, which specify new credentials.
    platform: sigma
    severity: low
    tactics:
      - lateral-movement
    techniques:
      - T1550
    data_sources:
      - windows
      - security
rules_count: 1
---

This rule monitors for Windows Security Event ID 4624 with Logon Type 9. This logon type indicates the use of new credentials.

## Recommendation

Monitor for instances of Logon Type 9. Note that this activity may also be associated with legitimate remote administration.

## Impact

This activity is associated with lateral movement techniques (T1550).
