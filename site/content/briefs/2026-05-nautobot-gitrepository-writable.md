---
title: Nautobot GitRepository current_head Field Writable via REST API (CVE-2026-44798)
slug: 2026-05-nautobot-gitrepository-writable
description: A user with permissions to modify GitRepository records can manipulate the `current_head` field via the REST API in Nautobot, leading to repository state desynchronization or unavailability; this is remediated in versions 2.4.33 and 3.1.2.
date: "2026-05-13T15:31:55Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - nautobot
  - gitrepository
  - rest-api
  - privilege-escalation
vendors:
  - Nautobot
products:
  - Nautobot ( < 2.4.33)
  - Nautobot (>= 3.0.0a2, < 3.1.2)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-p3hx-pwf3-j8wr
  - https://github.com/nautobot/nautobot/commit/9deddfc91ad9260ad17b5e20084e9e2d15be3609
  - https://github.com/nautobot/nautobot/commit/c46f97040b2bde4320be36b23577f19a8bcbd8c3
rules:
  - title: Detect API Requests to Modify Nautobot GitRepository current_head
    description: Detects CVE-2026-44798 exploitation — PUT/PATCH requests to the Nautobot GitRepository API endpoint with a 'current_head' parameter, indicating a potential attempt to directly modify the field.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
  - title: Detect Direct Modification of Nautobot GitRepository current_head via API
    description: Detects CVE-2026-44798 exploitation — Audit logs showing a user directly modifying the `current_head` field of a GitRepository object via the API.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 2
---

A vulnerability exists in Nautobot versions prior to 2.4.33 and between 3.0.0a2 and 3.1.2 that allows users with the ability to add or change GitRepository records to manipulate the `current_head` field through the REST API. This field, intended for internal use, dictates the commit hash that Nautobot's local clone of the repository checks out. By directly modifying this field, an attacker can force the local repository to an arbitrary state, potentially checking out an older commit, a non-existent commit, or a malformed value. This can lead to incorrect or misleading infrastructure state within Nautobot and may require manual intervention to resolve. The vulnerability, identified as CVE-2026-44798, was addressed in Nautobot versions 2.4.33 and 3.1.2.

## Attack Chain

1. An attacker authenticates to the Nautobot REST API with credentials that have permissions to modify GitRepository records.
2. The attacker identifies a GitRepository record they wish to manipulate.
3. The attacker crafts a REST API PUT or PATCH request to the GitRepository endpoint.
4. The request includes a modified `current_head` field containing a commit hash value. This value may be an older commit hash, a nonexistent commit hash, or a malformed string.
5. Nautobot processes the API request and updates the `current_head` field of the specified GitRepository record with the attacker-supplied value.
6. Nautobot's background processes attempt to synchronize the local Git repository clone with the updated `current_head`.
7. Depending on the value of `current_head`, the synchronization either checks out the specified commit, fails due to an invalid commit, or corrupts the local repository.
8. The attacker achieves the objective of desynchronizing Nautobot's view of the repository state or rendering the repository unusable.

## Impact

Successful exploitation of CVE-2026-44798 can cause Nautobot's view of network infrastructure to become inconsistent with the actual state represented in the Git repository. This can lead to misconfiguration, failed automation tasks, and general operational disruption. In the worst-case scenario, manual intervention is required to correct the `current_head` value and resynchronize the repository. The number of affected installations is unknown, but any Nautobot instance with users who can modify GitRepository objects is potentially vulnerable.

## Recommendation

*   Upgrade Nautobot to version 2.4.33 or 3.1.2 to address CVE-2026-44798.
*   Review and restrict user permissions to create and modify GitRepository records, as suggested in the advisory workaround.
*   Implement the detection rule "Detect Direct Modification of Nautobot GitRepository current_head via API" to monitor for unauthorized changes to the `current_head` field via the REST API.
*   Monitor webserver logs for PATCH or PUT requests to the `/api/extras/git-repositories/<id>/` endpoint that contain the `current_head` parameter, using a rule similar to "Detect API Requests to Modify Nautobot GitRepository current_head".
