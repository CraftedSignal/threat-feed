---
brief_id: brief-2026-10-23-zimbra-oauth-csrf
event_id: brief-2026-10-23-zimbra-oauth-csrf
revision: 1
activity_at: "2026-10-23T15:08:05Z"
title: 'Zimbra Collaboration Suite: Cross-site request forgery in OAuth extension (CVE-2026-93631)'
slug: 2026-10-zimbra-oauth-csrf
description: A cross-site request forgery vulnerability in the OAuth extension of Zimbra Collaboration Suite (ZCS) Network Edition allows an attacker to link an attacker-controlled external account to a victim's mailbox.
date: "2026-10-23T15:08:05Z"
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
  - cpe:2.3:a:zimbra:collaboration_suite_network_edition:*:*:*:*:*:*:*:*
vendors:
  - Zimbra
products:
  - Zimbra Collaboration Suite Network Edition (10.1.16, 10.1.20)
cves:
  - id: CVE-2026-93631
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-93631
---

A cross-site request forgery vulnerability exists in the OAuth extension of Zimbra Collaboration Suite (ZCS) Network Edition. The OAuth callback fails to bind its state value or authorization code to the initiating Zimbra session, instead selecting the destination mailbox from the browser's authentication cookie. 

On a deployment with the provider configured, an attacker can induce a signed-in victim to load a callback containing a fresh code for the attacker's provider account. This creates a persistent data source that imports attacker-controlled contacts or events. With bidirectional CalDAV synchronization, appointments created or edited in the linked calendar are disclosed to the attacker. ZCS 10.1.16 and 10.1.20 are affected.
