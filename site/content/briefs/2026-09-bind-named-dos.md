---
title: BIND 9 Named Denial of Service via Crafted DoH Requests
slug: 2026-09-bind-named-dos
description: A vulnerability in BIND 9 allows remote attackers to cause the 'named' process to abort by sending a crafted DNS-over-HTTPS request with an invalid SIG(0) record followed by premature connection closure.
date: "2026-09-16T15:50:18Z"
type: advisory
types:
  - advisory
severities:
  - low
cves:
  - id: CVE-2026-77692
    cvss: 7.5
---

CVE-2026-77692 is a denial-of-service vulnerability affecting the 'named' process in ISC BIND 9. The vulnerability is triggered when the server processes a DNS-over-HTTPS (DoH) request containing a cryptographically invalid SIG(0) record. If the transport connection is closed prematurely by the client after sending this malformed request, the BIND server experiences an assertion failure, leading to an immediate process abort. This vulnerability affects BIND versions 9.20.0 through 9.20.27, 9.21.0 through 9.21.25, and BIND 9 Subscription Edition (S1) versions 9.20.9-S1 through 9.20.27-S1. Because 'named' is a critical component of DNS infrastructure, successful exploitation results in an immediate service disruption for
