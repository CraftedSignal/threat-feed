---
title: Authorization Bypass in Kotaemon Conversation Management
slug: 2026-08-kotaemon-auth-bypass
description: Kotaemon through version 0.12.0 contains an authorization bypass vulnerability allowing unauthorized users to access, modify, or delete chat histories belonging to others.
date: "2026-08-29T01:35:40Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:kotaemon:kotaemon:*:*:*:*:*:*:*:*
vendors:
  - Kotaemon
products:
  - Kotaemon (<= 0.12.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: Attackers can read other users' chat histories, delete conversations, or rename conversations by supplying arbitrary conversation identifiers without proper authorization checks.
    confidence_band: high
cves:
  - id: CVE-2026-82281
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82281
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Restrict access to Kotaemon web interface until patched version is deployed
      owner: IT Operations
      due: 24h
      evidence: Vulnerability allows unauthorized access via arbitrary conversation IDs
  mitigation_plan:
    - priority: immediate
      action: Upgrade Kotaemon beyond version 0.12.0 once security patches are released
      owner: IT Operations
      addresses: CVE-2026-82281
      evidence: Source indicates vulnerability exists in versions through 0.12.0
---

Kotaemon through version 0.12.0 is susceptible to an authorization bypass vulnerability located in the conversation management functions of control.py. The affected functions include select_conv, delete_conv, rename_conv, and on_set_public_conversation. The application fails to perform adequate validation of conversation ownership when these functions are called, allowing an unauthenticated or low-privileged attacker to supply arbitrary conversation identifiers. By manipulating these identifiers, an attacker can read sensitive chat histories, rename existing conversations, or perform unauthorized deletions of historical data. This vulnerability poses a significant risk to data privacy and integrity within the application, as it circumvents intended access controls over user communications.

## Impact

Successful exploitation of this vulnerability allows unauthorized access to private user chat histories and the ability to perform destructive actions such as deleting or renaming conversations. This impact is significant in multi-user environments where conversation isolation is a security requirement. Organizations utilizing Kotaemon for internal AI-powered document analysis and chat should treat this as a high-risk issue until patches are applied.

## Recommendation

- Upgrade to a version of Kotaemon beyond 0.12.0 as soon as a patch is made available by the maintainers.
- Audit access logs for unexpected sequences of calls to control.py functions (select_conv, delete_conv, rename_conv) originating from a single user session that access multiple distinct conversation IDs.
- Implement network-level restrictions to ensure that instances of Kotaemon are not exposed to untrusted users or the public internet.
