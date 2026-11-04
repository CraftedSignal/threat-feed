---
brief_id: brief-2026-11-04-zbateson-crlf-injection
event_id: brief-2026-11-04-zbateson-crlf-injection
revision: 1
activity_at: "2026-11-04T14:47:58Z"
title: 'zbateson mail-mime-parser: CRLF header injection (CVE-2026-121946)'
slug: 2026-11-zbateson-crlf-injection
description: The zbateson mail-mime-parser library contains a CRLF header injection vulnerability in message-building helpers that fail to strip CR and LF characters.
date: "2026-11-04T14:47:58Z"
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
  - cpe:2.3:a:zbateson:mail_mime_parser:*:*:*:*:*:*:*:*
vendors:
  - zbateson
products:
  - mail-mime-parser (< 3.0.9, 4.x < 4.0.6)
cves:
  - id: CVE-2026-121946
    cvss: 7.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-121946
---

CVE-2026-121946 identifies a CRLF header injection vulnerability in zbateson mail-mime-parser versions before 3.0.9 and 4.x before 4.0.6. The vulnerability exists because message-building helpers fail to strip CR and LF characters. 

## Impact
Attackers supplying crafted MIME type, charset, encoding, micalg, or protocol values can inject extra header lines, such as a forged Bcc, into outgoing messages.
