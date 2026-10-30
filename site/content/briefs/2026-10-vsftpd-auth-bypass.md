---
brief_id: brief-2026-10-30-vsftpd-auth-bypass
event_id: brief-2026-10-30-vsftpd-auth-bypass
revision: 1
activity_at: "2026-10-30T13:29:53Z"
title: 'vsftpd: Authentication bypass in ssl_data_accept (CVE-2026-119568)'
slug: 2026-10-vsftpd-auth-bypass
description: vsftpd through 3.0.5 contains an authentication bypass vulnerability in ssl_data_accept() that allows unauthenticated attackers to hijack FTPS data connections.
date: "2026-10-30T13:29:53Z"
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
products:
  - vsftpd (through 3.0.5)
cves:
  - id: CVE-2026-119568
    cvss: 7.4
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119568
---

vsftpd through 3.0.5 contains an authentication bypass vulnerability in ssl_data_accept() that allows unauthenticated attackers to hijack FTPS data connections by resuming their own TLS session ticket. Attackers sharing the victim's source IP can obtain a ticket via AUTH TLS, then connect to the victim's PASV port to steal downloads or inject upload data.
