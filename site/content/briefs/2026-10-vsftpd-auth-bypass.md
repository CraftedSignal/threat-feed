---
brief_id: brief-2026-10-30-vsftpd-auth-bypass
event_id: brief-2026-10-30-vsftpd-auth-bypass
revision: 2
activity_at: "2026-10-30T13:42:47Z"
revision_history:
  - revision: 2
    at: "2026-10-30T13:42:47Z"
    checksum: sha256:7c63047109b7b70aa569593fa70acb6107f1726d93e02d2823f4b7aa751a405a
    summary: poc_available
    changed_fields:
      - claim_state
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-119568&utm_source=rss&utm_medium=rss
title: 'vsftpd: Authentication bypass in ssl_data_accept (CVE-2026-119568)'
slug: 2026-10-vsftpd-auth-bypass
description: vsftpd through 3.0.5 contains an authentication bypass vulnerability in ssl_data_accept() that allows unauthenticated attackers to hijack FTPS data connections.
date: "2026-10-30T13:29:53Z"
lastmod: "2026-10-30T13:41:58Z"
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
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=CVE-2026-119568&utm_source=rss&utm_medium=rss
products:
  - vsftpd (through 3.0.5)
cves:
  - id: CVE-2026-119568
    cvss: 7.4
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119568
  - https://sploitus.com/exploit?id=CVE-2026-119568&utm_source=rss&utm_medium=rss
updates:
  - at: "2026-10-30T13:41:58Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-119568&utm_source=rss&utm_medium=rss
---

vsftpd through 3.0.5 contains an authentication bypass vulnerability in ssl_data_accept() that allows unauthenticated attackers to hijack FTPS data connections by resuming their own TLS session ticket. Attackers sharing the victim's source IP can obtain a ticket via AUTH TLS, then connect to the victim's PASV port to steal downloads or inject upload data.
