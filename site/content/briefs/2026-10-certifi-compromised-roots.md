---
brief_id: brief-2026-10-20-certifi-compromised-roots
event_id: brief-2026-10-20-certifi-compromised-roots
revision: 3
activity_at: "2026-10-20T23:53:18Z"
revision_history:
  - revision: 2
    at: "2026-10-21T07:09:10Z"
    checksum: sha256:46058700ab766a8d3778e7ceae5de35d4406aa24c255a48b05d1505624cb002c
    summary: Corrected the first patched certifi version and removed unsupported attack details.
    changed_fields:
      - description
      - tags
      - products
      - mitre_ttps
      - references
      - action_plan
      - body
    source_urls:
      - https://github.com/certifi/python-certifi/security/advisories/GHSA-6q48-6c7w-9gw2
      - https://blog.mozilla.org/security/2026/10/20/protecting-firefox-users-following-the-compromise-of-emudhra-intermediate-certificates/
    maintenance: true
  - revision: 3
    at: "2026-10-21T13:09:06Z"
    checksum: sha256:c428ab3703b79f4f52939f54bbb31b957f30e211dfb6d014873c4ae4a3b057cd
    summary: Retired this downstream duplicate page in favor of the consolidated eMudhra incident brief.
    changed_fields:
      - draft
    maintenance: true
draft: true
title: 'Certifi: Bundled eMudhra root CAs with compromised intermediate keys'
slug: 2026-10-certifi-compromised-roots
description: Certifi versions before 2026.10.18 included emSign roots whose intermediate keys were compromised. An attacker able to position on path could use a fraudulent certificate to intercept TLS traffic.
date: "2026-10-20T23:53:18Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
qa_status:
  verdict: pass
tags:
  - certificate-authority
  - tls-interception
  - python
vendors:
  - eMudhra
products:
  - certifi (< 2026.10.18)
references:
  - https://github.com/certifi/python-certifi/security/advisories/GHSA-6q48-6c7w-9gw2
  - https://blog.mozilla.org/security/2026/10/20/protecting-firefox-users-following-the-compromise-of-emudhra-intermediate-certificates/
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade certifi to 2026.10.18 or later in affected environments
      owner: IT Operations
      due: 24h
      evidence: The certifi maintainer lists 2026.10.18 as the first patched version.
  mitigation_plan:
    - priority: immediate
      action: Rebuild container images that vendor certifi
      owner: IT Operations
      addresses: certifi (< 2026.10.18)
      evidence: Images with older bundled certifi releases retain the affected trust store until rebuilt.
---

The certifi maintainer removed emSign root certificates from the bundled CA store in version 2026.10.18 after intermediates chaining to those roots were revoked for key compromise. Mozilla separately reported the compromise of eight eMudhra intermediate certificates. A compromised CA key can enable fraudulent certificates and a man-in-the-middle attack when an attacker is on path. The cited advisories do not report an observed attack against certifi users.

## Impact

Applications that use an affected certifi CA bundle for TLS validation may trust certificates issued through the compromised intermediates. The risk depends on whether the application uses that bundle and whether an attacker can intercept its connection.

## Recommendation

- Identify applications and images that use certifi versions before 2026.10.18.
- Upgrade affected installations to certifi 2026.10.18 or later and rebuild images that bundle an older release.
- Check which TLS clients use certifi rather than an operating-system trust store so remediation targets the affected paths.
