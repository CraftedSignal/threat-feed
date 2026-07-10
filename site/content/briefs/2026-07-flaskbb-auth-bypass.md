---
title: FlaskBB Authorization Bypass Vulnerability (CVE-2026-22659)
slug: 2026-07-flaskbb-auth-bypass
description: An authorization bypass vulnerability exists in FlaskBB through version 2.2.0, allowing authenticated moderators to perform unauthorized administrative actions such as locking, unlocking, deleting, or hiding topics in forums they do not control. This is achieved by crafting batch requests that include a low-ID topic from a permitted forum, which bypasses permission checks applied only to the first item, and then executing actions on topics from unmoderated forums.
date: "2026-07-10T14:18:45Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authorization-bypass
  - vulnerability
  - web-application
vendors:
  - FlaskBB
products:
  - FlaskBB <= 2.2.0
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: authorization bypass vulnerability that ... allows authenticated moderators to perform unauthorized actions
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: allows authenticated moderators to perform unauthorized actions on topics in forums they do not control
    confidence_band: high
cves:
  - id: CVE-2026-22659
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-22659
---

FlaskBB through version 2.2.0 is affected by an authorization bypass vulnerability, identified as CVE-2026-22659, which enables authenticated moderators to execute unauthorized administrative actions. This flaw allows a moderator, who normally has permissions only within specific forums, to extend their control to topics in forums they do not oversee. The exploitation mechanism involves submitting specially crafted batch requests where a legitimate topic ID from a permitted forum is included as an "anchor." This tricks the application into passing its permission check, which is only applied to the first item in the batch. Subsequently, the attacker can perform actions like locking, unlocking, deleting, or hiding topics in forums they are not authorized to moderate, effectively escalating their privileges within the application. This vulnerability impacts all installations of FlaskBB up to version 2.2.0 and was addressed in commit acc88cf.

## Attack Chain

1. An attacker obtains valid moderator credentials for a FlaskBB forum instance.
2. The attacker identifies forums within the FlaskBB instance where their moderator account lacks administrative privileges.
3. The attacker then identifies specific topics within these unauthorized forums that they wish to manipulate (e.g., delete, lock).
4. Concurrently, the attacker identifies a low-ID topic in a forum where their moderator account *does* possess legitimate moderation privileges. This topic will serve as the bypass "anchor."
5. The attacker constructs a batch request for a moderation action (e.g., lock, delete, hide) that includes both the legitimate low-ID topic from a permitted forum and the target topics from the unauthorized forums.
6. The crafted batch request is submitted to the FlaskBB application's moderation endpoint.
7. Due to the authorization bypass vulnerability (CVE-2026-22659), the FlaskBB application performs its permission check only on the first topic in the batch (the legitimate low-ID topic). Since the attacker has permissions for this topic, the check passes.
8. The application proceeds to execute the requested moderation action across all topics in the batch, including those in forums where the attacker otherwise lacks permission, achieving unauthorized administrative control.

## Impact

A successful exploitation of CVE-2026-22659 allows an authenticated attacker to perform unauthorized administrative actions such as locking, unlocking, deleting, or hiding topics across any forum within a FlaskBB instance. While it does not grant full system access, it can lead to significant content integrity issues, disruption of forum operations, and reputational damage for the affected organizations. Organizations relying on FlaskBB for community management may face challenges in maintaining trust and order if malicious actors gain the ability to arbitrarily manipulate content in forums they do not control. The CVSS v3.1 Base Score for this vulnerability is 8.1, indicating a high severity risk.

## Recommendation

* Patch FlaskBB installations immediately to a version beyond 2.2.0, ensuring the fix introduced in commit acc88cf for CVE-2026-22659 is applied.
* Monitor web server access logs for FlaskBB for any suspicious batch moderation requests, especially those originating from known moderator accounts manipulating topics outside their assigned forums, which could indicate exploitation of CVE-2026-22659.
* Review FlaskBB application logs for unusual administrative actions or error messages related to topic moderation, which might signal attempts to exploit this authorization bypass vulnerability.
