---
title: 'CVE-2026-58593: NodeBB ActivityPub Forgery Vulnerability'
slug: 2026-07-nodebb-activitypub-forgery
description: A critical vulnerability (CVE-2026-58593) in NodeBB's ActivityPub implementation allows a remote attacker to forge posts and direct messages attributed to arbitrary local users, including administrators, by manipulating the 'attributedTo' field in inbound ActivityPub objects.
date: "2026-07-01T20:28:02Z"
lastmod: "2026-07-24T08:44:57Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:nodebb:nodebb:*:*:*:*:*:*:*:*
has_poc: true
tags:
  - activitypub
  - federation
  - vulnerability
  - web-application
  - cms
  - forgery
vendors:
  - NodeBB
products:
  - NodeBB
  - NodeBB < 4.14.0
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: a federated remote actor can set attributedTo to a bare numeric value such as 1 and have the resulting post or private message created with that local uid as author
    confidence_band: high
cves:
  - id: CVE-2026-58593
    cvss: 7.5
    epss: 0.00191
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-58593
  - https://thehackernews.com/2026/07/nodebb-patches-eight-ai-found-flaws.html
updates:
  - at: "2026-07-24T08:44:57Z"
    level: L2
    summary: poc_available
    sources:
      - the-hacker-news
    source_urls:
      - https://thehackernews.com/2026/07/nodebb-patches-eight-ai-found-flaws.html
---

A significant vulnerability, tracked as CVE-2026-58593, has been identified in NodeBB's ActivityPub federation feature. This flaw permits a remote attacker to craft and send malicious ActivityPub objects that appear to originate from legitimate local NodeBB users, including administrative accounts. The core issue lies in NodeBB's failure to properly bind the `attributedTo` field in inbound ActivityPub objects to the authenticated remote actor, despite verifying the HTTP signature and object origin. By setting `attributedTo` to a bare numeric User ID (UID) such as `1` (which commonly corresponds to the administrator), an attacker can bypass validation and cause the system to create posts or private messages falsely attributed to that local UID. This vulnerability, which requires the ActivityPub/federation feature to be enabled, poses a serious risk of unauthorized content creation, misinformation, and potential reputational damage within affected NodeBB instances.

## Attack Chain

1.  **Initial Access / Reconnaissance**: An attacker identifies a NodeBB instance with the ActivityPub/federation feature enabled. They may collect information on local user UIDs, potentially through publicly available profiles or by guessing common administrator UIDs (e.g., `1`).
2.  **Object Crafting**: The attacker crafts a malicious ActivityPub `object` that includes a `attributedTo` field set to the numeric UID of a target local NodeBB user (e.g., `1` for the administrator).
3.  **HTTP Signature**: The attacker ensures the malicious ActivityPub object has a valid HTTP-signature corresponding to their own remote ActivityPub actor.
4.  **Origin Check Bypass**: The attacker ensures the `object.id` in their crafted ActivityPub object corresponds to an origin they control or one that would pass NodeBB's origin checks.
5.  **Inbound Delivery**: The crafted ActivityPub object is sent to the vulnerable NodeBB instance's ActivityPub inbox endpoint.
6.  **Failed Validation**: NodeBB's inbound middleware verifies the HTTP signature and `object.id` origin, but critically fails to validate that the `attributedTo` field matches the authenticated remote actor or is a non-numeric identifier.
7.  **Content Creation**: Due to the bypass, NodeBB's `actors.assert` function silently ignores the numeric `attributedTo` identifier, allowing the system to use the provided numeric UID directly as the author of the incoming post or private message.
8.  **Impact**: The malicious post or private message is created and attributed to the targeted local NodeBB user, effectively forging content from their account. This can include administrative messages or sensitive private communications.

## Impact

Successful exploitation of CVE-2026-58593 allows a remote attacker to impersonate any local user on an affected NodeBB instance, including the administrator. This directly leads to the creation of forged posts and direct messages, which can result in severe reputational damage to individuals or the organization running the forum. Attackers could spread misinformation, issue unauthorized announcements, or send malicious links via direct messages under the guise of a trusted user. The lack of proper author validation means that evidence of compromise would initially point to a legitimate internal user, making incident response and attribution more complex. The extent of the impact depends on the privileges and perceived trustworthiness of the impersonated account.

## Recommendation

*   **Patch CVE-2026-58593**: Immediately apply the vendor-provided patch for CVE-2026-58593 to all affected NodeBB instances to address the vulnerability in the ActivityPub implementation.
*   **Review ActivityPub Feature**: If patching is not immediately feasible, evaluate the necessity of the ActivityPub/federation feature. If not essential, consider disabling it temporarily to mitigate the risk posed by CVE-2026-58593.
*   **Educate Users**: Inform users, especially administrators, about the potential for forged messages and posts, emphasizing vigilance regarding suspicious content, even if it appears to come from trusted sources.
