---
brief_id: brief-2026-11-09-supertokens-core-session-validation
event_id: brief-2026-11-09-supertokens-core-session-validation
revision: 1
activity_at: "2026-11-09T21:59:35Z"
title: 'SuperTokens Core: Dashboard session expiry validation bypass (CVE-2026-123799)'
slug: 2026-11-supertokens-core-session-validation
description: SuperTokens Core fails to validate dashboard session expiry at the API level, relying instead on a periodic cleanup task.
date: "2026-11-09T21:59:35Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:supertokens:core:*:*:*:*:*:*:*:*
vendors:
  - SuperTokens
products:
  - SuperTokens Core (11.0.0-11.0.8)
cves:
  - id: CVE-2026-123799
    cvss: 7.4
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-123799
---

SuperTokens Core versions 11.0.0 through 11.0.8, 11.1.0 through 11.1.3, 11.2.0 through 11.2.3, 11.3.0 through 11.3.7, 11.4.0 through 11.4.7, 12.0.0 through 12.0.10, and 12.1.0 through 12.1.1 contain a vulnerability where `Dashboard.isValidUserSession` and `DashboardQueries.getSessionInfoWithSessionId` do not compare `DashboardSessionInfo.expiry` to the current time. 

## Impact
The system relies on the `DeleteExpiredDashboardSessions` task for expiration enforcement. An attacker who has obtained a dashboard administrator session can continue to use it via `POST /recipe/dashboard/session/verify` until the row is removed. Frequent Core restarts may prevent the 12-hour cleanup sweep, extending the window of access. The flaw does not allow for guessing or acquiring the random session identifier.
