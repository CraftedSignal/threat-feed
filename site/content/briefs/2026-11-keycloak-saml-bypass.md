---
brief_id: brief-2026-11-05-keycloak-saml-bypass
event_id: brief-2026-11-05-keycloak-saml-bypass
revision: 2
activity_at: "2026-11-05T16:33:05Z"
revision_history:
  - revision: 2
    at: "2026-11-05T16:33:05Z"
    checksum: sha256:c14ff2826bf90ecfc962a4907940acc39f0a5f2abb086191836d230fc677eb3e
    summary: poc_available
    changed_fields:
      - affected_products
      - affected_vendors
      - claim_state
      - cpes
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-117691&utm_source=rss&utm_medium=rss
title: 'Keycloak: Authentication bypass via SAML HTTP-Redirect binding (CVE-2026-117691)'
slug: 2026-11-keycloak-saml-bypass
description: A flaw in Keycloak's SAML HTTP-Redirect binding implementation allows an attacker to bypass signature verification using percent-encoded parameter names, potentially leading to full account takeover of federated users.
date: "2026-11-05T14:40:31Z"
lastmod: "2026-11-05T16:32:13Z"
type: advisory
claim_state: <nil>
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
  - cpe:2.3:a:red_hat:keycloak:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=CVE-2026-117691&utm_source=rss&utm_medium=rss
vendors:
  - Red Hat
products:
  - Keycloak
cves:
  - id: CVE-2026-117691
    cvss: 9.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-117691
  - https://sploitus.com/exploit?id=CVE-2026-117691&utm_source=rss&utm_medium=rss
updates:
  - at: "2026-11-05T16:32:13Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-117691&utm_source=rss&utm_medium=rss
---

A flaw was found in the SAML HTTP-Redirect binding implementation of Keycloak (CVE-2026-117691). The issue occurs because the server processes percent-encoded parameter names (like %53AMLResponse) while the signature verification logic only checks literal parameter names. An attacker can use this discrepancy to provide a crafted, unsigned SAML message that the server processes instead of a legitimately signed one, leading to full account takeover of federated users.
