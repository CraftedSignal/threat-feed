---
brief_id: brief-2026-10-22-libsmb2-integer-overflow
event_id: brief-2026-10-22-libsmb2-integer-overflow
revision: 1
activity_at: "2026-10-22T22:31:11Z"
title: 'libsmb2: Integer overflow in DCE/RPC NDR decoder (CVE-2026-115505)'
slug: 2026-10-libsmb2-integer-overflow
description: libsmb2 before 6.3 contains integer overflow vulnerabilities in the DCE/RPC NDR decoder in lib/dcerpc.c that allow heap out-of-bounds reads and writes.
date: "2026-10-22T22:31:11Z"
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
  - libsmb2 (< 6.3)
cves:
  - id: CVE-2026-115505
    cvss: 7.6
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115505
---

libsmb2 before 6.3 contains integer overflow vulnerabilities in the DCE/RPC NDR decoder in lib/dcerpc.c. A malicious SMB server or machine-in-the-middle on unsigned connections can send crafted NetrShareEnum replies with wrapping actual_count or max_count values when clients call smb2_share_enum_async(), corrupting heap memory.
