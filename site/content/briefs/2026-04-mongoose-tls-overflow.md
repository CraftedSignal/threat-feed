---
title: Cesanta Mongoose TLS 1.3 Heap-Based Buffer Overflow Vulnerability (CVE-2026-5244)
slug: 2026-04-mongoose-tls-overflow
description: A remote heap-based buffer overflow vulnerability exists in Cesanta Mongoose versions up to 7.20 due to improper handling of the pubkey argument in the mg_tls_recv_cert function, potentially leading to code execution.
date: "2026-04-02T08:16:28Z"
severities:
  - high
tags:
  - cve-2026-5244
  - heap-based-buffer-overflow
  - tls-1.3
  - remote-code-execution
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5244
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5244
rules:
  - title: Detect CVE-2026-5244 Exploitation Attempt via TLS Handshake
    description: Detects potential attempts to exploit CVE-2026-5244 by monitoring for abnormal TLS handshake patterns indicative of oversized pubkey values.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Large POST Request - Possible CVE-2026-5244 Exploit
    description: Detects unusually large POST requests, potentially indicative of an attempt to trigger a heap overflow in the TLS 1.3 handler.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A heap-based buffer overflow vulnerability, identified as CVE-2026-5244, has been discovered in Cesanta Mongoose versions up to 7.20. This flaw resides within the `mg_tls_recv_cert` function in the `mongoose.c` file, specifically affecting the TLS 1.3 handler. The vulnerability can be triggered by manipulating the `pubkey` argument, which leads to memory corruption. The exploit for this vulnerability is publicly available, increasing the risk of exploitation. Successful exploitation could allow…
