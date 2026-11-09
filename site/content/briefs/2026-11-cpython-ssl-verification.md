---
brief_id: brief-2026-11-09-cpython-ssl-verification
event_id: brief-2026-11-09-cpython-ssl-verification
revision: 1
activity_at: "2026-11-09T21:17:02Z"
title: 'CPython: ssl.get_server_certificate fails identity verification (CVE-2026-19552)'
slug: 2026-11-cpython-ssl-verification
description: CPython vulnerability CVE-2026-19552 affects ssl.get_server_certificate(addr, ca_certs=...), which verifies the certificate chain but does not verify the identity.
date: "2026-11-09T21:17:02Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: unknown
products:
  - CPython
cves:
  - id: CVE-2026-19552
    kev_status: "false"
references:
  - https://seclists.org/oss-sec/2026/q4/605
---

The Python Software Foundation has announced a low-severity vulnerability in CPython (CVE-2026-19552). When the `ca_certs` parameter is supplied to `ssl.get_server_certificate`, the function verifies the certificate chain but fails to verify the identity.
