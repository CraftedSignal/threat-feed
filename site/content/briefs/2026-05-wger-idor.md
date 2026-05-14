---
title: wger IDOR Vulnerability Exposes Private Workout Data (CVE-2026-43977)
slug: 2026-05-wger-idor
description: wger 2.5 and earlier is vulnerable to CVE-2026-43977, an Insecure Direct Object Reference (IDOR) vulnerability that allows any authenticated user to read another user's private workout session notes, exercise history, and training statistics by accessing the `/logs/` and `/stats/` actions on a public template routine they do not own.
date: "2026-05-14T16:20:03Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - idor
  - vulnerability
  - data-breach
  - cloud
vendors:
  - wger
products:
  - wger (<= 2.5)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1213
    technique_name: Insecure Direct Object Reference
references:
  - https://github.com/advisories/GHSA-cj9g-27ph-4cgv
  - CVE-2026-43977
rules:
  - title: Detect Unauthorized Workout Logs Access
    description: Detects CVE-2026-43977 exploitation — unauthorized access to workout logs via /api/v2/routine/{id}/logs/ by non-owners.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1213
    data_sources:
      - webserver
  - title: Detect Unauthorized Workout Statistics Access
    description: Detects CVE-2026-43977 exploitation — unauthorized access to workout statistics via /api/v2/routine/{id}/stats/ by non-owners.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1213
    data_sources:
      - webserver
rules_count: 2
---

wger, a web-based workout manager, is vulnerable to an IDOR flaw (CVE-2026-43977) affecting versions 2.5 and earlier. This vulnerability allows any authenticated user, even with a free account, to access the private workout data of other users if they have created a public template routine. The vulnerability resides in the `RoutineViewSet` within `wger/manager/api/views.py`, specifically in the `/logs/` and `/stats/` actions. An attacker can enumerate all public template routines and then call these vulnerable endpoints to retrieve the routine owner's workout logs, notes, and statistics. This exposes sensitive health-related data, potentially violating privacy regulations like GDPR.

## Attack Chain

1.  Attacker registers a free account on the wger instance and obtains a JWT access token via `POST /api/v2/token`.
2.  Attacker calls `GET /api/v2/routine/?is_template=true&is_public=true` to enumerate all public template routines from all users across the platform, including their IDs.
3.  For each returned routine ID, the attacker calls `GET /api/v2/routine/{id}/logs/`.
4.  The server retrieves the requested routine details using `self.get_object()`. Due to insufficient permission checks, the server grants the attacker access to the routine's data because `is_template=True`.
5.  The `logs_display()` function returns the workout sessions, including freeform personal notes and all logged exercises with weights and reps for the **routine owner**, not the attacker.
6.  The attacker then calls `GET /api/v2/routine/{id}/stats/` to get aggregated statistics (total volume, intensity by muscle group, weekly progression) for the routine's owner.
7.  The `calculate_log_statistics()` function calculates statistics for the routine owner, not the attacker, because there is no user context checking.
8. The attacker exfiltrates the sensitive workout data of other users, including personal notes, workout history, and training statistics.

## Impact

Successful exploitation of this IDOR vulnerability allows an attacker to access sensitive, health-related data of other wger users. An attacker can enumerate all public templates and then read private workout session notes, full workout history, and training statistics of the routine owner. This unauthorized access to personal health data constitutes a data breach under regulations like GDPR, leading to potential legal and reputational damage for the wger platform.

## Recommendation

*   Apply the recommended fix provided in the advisory, modifying the `/logs/` and `/stats/` actions in `wger/manager/api/views.py` to filter results to the requesting user, as described in the advisory.
*   Implement the stricter permission checks in `RoutinePermission.has_object_permission` to deny access to the `/logs/` and `/stats/` actions for non-owners, regardless of `is_template`, as described in the advisory.
*   Deploy the following Sigma rule to detect unauthorized access to workout logs using the vulnerable endpoint: [Detect Unauthorized Workout Logs Access].
*   Deploy the following Sigma rule to detect unauthorized access to workout statistics using the vulnerable endpoint: [Detect Unauthorized Workout Statistics Access].
