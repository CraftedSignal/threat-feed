---
title: 'CVE-2026-65013: Onlook Broken Object Level Authorization Vulnerability'
slug: 2026-07-onlook-bola
description: An authorization bypass vulnerability, CVE-2026-65013, exists in Onlook through version 0.2.32, allowing authenticated attackers to access and manipulate other users' resources by supplying arbitrary UUID values to tRPC API procedures such as project.get, member.remove, and chat.conversation.delete without proper authorization, leading to unauthorized data exposure, modification, or deletion.
date: "2026-07-22T17:19:43Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authorization-bypass
  - api-abuse
  - cve
vendors:
  - Onlook
products:
  - Onlook (<= 0.2.32)
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1530
    technique_name: Data from Cloud Storage
    evidence: access and manipulate other users' resources by supplying arbitrary UUID values to tRPC API procedures including project.get
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: delete other users' project data, members, and conversation history.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: manipulate other users' resources by supplying arbitrary UUID values to tRPC API procedures including ... member.remove
    confidence_band: high
cves:
  - id: CVE-2026-65013
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-65013
---

A critical broken object level authorization (BOLA) vulnerability, identified as CVE-2026-65013, has been discovered in Onlook software, affecting versions up to and including 0.2.32. This flaw allows an authenticated attacker to bypass authorization checks within the application's tRPC API. By crafting requests with arbitrary UUIDs (e.g., `projectId`, `conversationId`) for specific procedures like `project.get`, `member.remove`, and `chat.conversation.delete`, attackers can gain unauthorized access to other users' project data, modify member information, and delete conversation histories. This vulnerability poses a significant risk of data breach, integrity compromise, and denial of service for affected users, as it enables full control over sensitive data and user accounts belonging to other individuals on the same platform. The vulnerability was fixed in commit 423e2e9.

## Attack Chain

1. An authenticated attacker gains access to a legitimate user account within the vulnerable Onlook application.
2. The attacker identifies tRPC API procedures susceptible to broken object level authorization, specifically `project.get`, `member.remove`, and `chat.conversation.delete`.
3. The attacker intercepts or crafts API requests for these target procedures.
4. The attacker replaces the legitimate UUIDs (e.g., `projectId`, `conversationId`) in the request parameters with arbitrary UUIDs belonging to other users or resources they do not own.
5. The Onlook application processes these requests without performing adequate authorization checks to verify if the authenticated user has legitimate access to the supplied arbitrary UUID.
6. The application performs the requested action (read, modify, delete) on the resources associated with the arbitrary UUID, effectively bypassing object-level authorization.
7. The attacker successfully reads other users' project data, removes members from projects, or deletes other users' chat conversation histories, achieving unauthorized data access, manipulation, or destruction.

## Impact

Successful exploitation of CVE-2026-65013 allows authenticated attackers to fully compromise the privacy and integrity of other users' data within the Onlook platform. Attackers can gain complete unauthorized access to sensitive project data, modify or delete critical information, and disrupt collaboration by removing project members. Furthermore, they can delete entire conversation histories, leading to significant data loss and potential compliance issues. While specific victim counts are not available, all users of Onlook versions 0.2.32 and earlier are at risk, with potential consequences including reputational damage, financial losses due to data breaches, and a complete loss of trust in the platform's security.

## Recommendation

* Patch CVE-2026-65013 by updating Onlook to a version beyond 0.2.32, specifically incorporating the fix from commit 423e2e9, immediately.
* Implement API gateway logging and monitoring to detect unusual patterns in tRPC API calls, such as repeated attempts to access various `projectId` or `conversationId` values by a single user, specifically for procedures like `project.get`, `member.remove`, and `chat.conversation.delete`.
* Review application-level logs for signs of unauthorized data access, modification, or deletion linked to arbitrary UUID values.
