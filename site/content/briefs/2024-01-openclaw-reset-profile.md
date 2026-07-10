---
title: 'OpenClaw: Unauthorized Profile Reset via browser.request'
slug: 2024-01-openclaw-reset-profile
description: OpenClaw version 2026.3.22 allows authenticated users with `operator.write` access to the `browser.request` method to reset persistent browser profiles via a `POST /reset-profile` request due to a missing check in the persistent-profile mutation classifier, leading to data loss and service disruption.
date: "2024-01-02T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - openclaw
  - authorization
  - profile-reset
vendors:
  - OpenClaw
products:
  - OpenClaw
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-xp9r-prpg-373r
rules:
  - title: Detect OpenClaw Unauthorized Profile Reset
    description: Detects unauthorized profile reset attempts in OpenClaw by monitoring for POST requests to /reset-profile through the browser.request method.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    data_sources:
      - webserver
      - linux
  - title: OpenClaw browser.request /reset-profile
    description: Detects calls to the /reset-profile endpoint via the browser.request method in OpenClaw, indicative of potential unauthorized profile resets.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

OpenClaw version 2026.3.22 contains an authorization bypass vulnerability that allows an authenticated user with limited `operator.write` privileges to perform destructive actions on browser profiles. Specifically, a user with access to the `browser.request` Gateway method can send a `POST` request to the `/reset-profile` endpoint, which is intended for higher-privileged users. This is due to an incomplete fix related to persistent profile management. While the prior fix blocked `POST /profiles/create` and profile deletion, the latest release omits `POST /reset-profile` from the same mutation gate. This vulnerability was addressed in OpenClaw version 2026.3.24.

## Attack Chain

1. An attacker authenticates to the OpenClaw application with `operator.write` privileges.
2. The attacker leverages their access to the `browser.request` Gateway method.
3. The attacker crafts a `POST` request to the `/reset-profile` endpoint. The request body includes the target profile name.
4. The `browser.request` method incorrectly forwards the request to the browser route dispatcher due to a missing check in the `isPersistentBrowserProfileMutation(...)` helper.
5. The exposed browser server route maps `/reset-profile` to `profileCtx.resetProfile()`.
6. The `resetProfile()` function is executed, stopping the running browser, closing the Playwright browser connection, and moving the profile's `userDataDir` to Trash.
7. The target browser profile is reset, leading to data loss and service disruption for the user associated with that profile.

## Impact

Successful exploitation of this vulnerability allows an attacker with `operator.write` access to reset arbitrary browser profiles. This results in the targeted browser being stopped, the Playwright browser connection being closed, and the profile's local data directory being moved to the trash. This leads to a loss of persistent browser state, potential data loss, and disruption of service for users relying on the affected browser profiles.

## Recommendation

*   Upgrade OpenClaw to version 2026.3.24 or later to patch the vulnerability.
*   Deploy the Sigma rule `Detect OpenClaw Unauthorized Profile Reset` to detect exploitation attempts by monitoring for `POST` requests to `/reset-profile` originating from `browser.request` with `operator.write` privileges.
*   Review the source code locations `src/gateway/server-methods/browser.ts` and `src/node-host/invoke-browser.ts` to ensure all profile-management routes are correctly classified and protected.
*   Implement regression testing with a deny control for `POST /reset-profile` on the `browser.request` surface to prevent future regressions.
