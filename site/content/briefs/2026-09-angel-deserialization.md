---
title: Remote Code Execution and DoS in Angel via Kryo Deserialization
slug: 2026-09-angel-deserialization
description: Angel versions 3.3.0 and earlier are vulnerable to a deserialization flaw allowing unauthenticated remote attackers to trigger arbitrary code execution or denial-of-service via the master RPC endpoint.
date: "2026-09-16T21:56:42Z"
type: advisory
types:
  - advisory
severities:
  - high
cves:
  - id: CVE-2026-92785
    cvss: 8.1
---

Angel versions 3.3.0 and earlier contain a critical deserialization vulnerability (CVE-2026-92785) stemming from the improper
