---
brief_id: brief-2026-10-31-apache-mina-deserialization
event_id: brief-2026-10-31-apache-mina-deserialization
revision: 1
activity_at: "2026-10-31T09:42:43Z"
title: 'Apache MINA: Unsafe Deserialization in JavaNativeMessageDecoder (CVE-2026-118636)'
slug: 2026-10-apache-mina-deserialization
description: Apache MINA versions 3.0.0 through 3.0.0-M2 are vulnerable to remote code execution due to unsafe deserialization in the JavaNativeMessageDecoder class.
date: "2026-10-31T09:42:43Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: D
  credibility: "3"
  rating: D3
  likelihood: roughly even chance
products:
  - Apache MINA (3.0.0 through 3.0.0-M2)
cves:
  - id: CVE-2026-118636
    kev_status: unknown
references:
  - https://seclists.org/oss-sec/2026/q4/457
---

Apache MINA versions 3.0.0 through 3.0.0-M2 contain a critical deserialization vulnerability (CVE-2026-118636) in the `JavaNativeMessageDecoder` component. The vulnerability exists because `JavaNativeMessageDecoder` calls `ObjectInputStream.readObject()` on frame bytes without a class filter. Applications using this decoder to process data from untrusted peers are susceptible to gadget-chain remote code execution.
