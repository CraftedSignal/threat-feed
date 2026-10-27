---
brief_id: brief-2026-10-27-semantic-mediawiki-csrf
event_id: brief-2026-10-27-semantic-mediawiki-csrf
revision: 1
activity_at: "2026-10-27T11:46:42Z"
title: 'Semantic MediaWiki: Cross-site request forgery in Special:SMWAdmin (CVE-2026-116880)'
slug: 2026-10-semantic-mediawiki-csrf
description: Semantic MediaWiki from 3.0.0 before 7.3.1 contains a cross-site request forgery vulnerability in Special:SMWAdmin, allowing an attacker to trigger unauthorized administrative actions.
date: "2026-10-27T11:46:42Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: not_observed
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
products:
  - Semantic MediaWiki (3.0.0 before 7.3.1)
cves:
  - id: CVE-2026-116880
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116880
---

Semantic MediaWiki from 3.0.0 before 7.3.1 contains a cross-site request forgery (CSRF) vulnerability in Special:SMWAdmin. The vulnerability occurs because the application overwrites the wpEditToken with a freshly generated valid token. An attacker can lure an authenticated smw-admin user to a malicious page that triggers schema setup, entity-disposal, or job actions, potentially resulting in semantic data loss and resource exhaustion.
