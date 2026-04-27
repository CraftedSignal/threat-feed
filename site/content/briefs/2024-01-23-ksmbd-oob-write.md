---
title: ksmbd Out-of-Bounds Write Vulnerability in QUERY_INFO (CVE-2026-31432)
slug: 2024-01-23-ksmbd-oob-write
description: CVE-2026-31432 is a critical out-of-bounds write vulnerability in ksmbd, specifically within the QUERY_INFO functionality when handling compound requests, potentially leading to code execution or denial of service.
date: "2024-01-23T12:00:00Z"
severities:
  - critical
tags:
  - ksmbd
  - smb
  - out-of-bounds write
  - cve-2026-31432
vendors:
  - Microsoft
cves:
  - id: CVE-2026-31432
    epss: 8e-05
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-31432
rules:
  - title: Detect Suspicious SMBv1 Negotiation
    description: Detects SMBv1 negotiation which may indicate older, vulnerable systems or attempts to downgrade connections.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566
    data_sources:
      - network_connection
      - windows
  - title: Detect High Number of SMB Errors
    description: Detects a high number of SMB errors, potentially indicating exploitation attempts or misconfiguration issues.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

CVE-2026-31432 is a critical vulnerability affecting the ksmbd server, a Linux kernel implementation of the SMB/CIFS protocol. The vulnerability is an out-of-bounds write that occurs when processing QUERY_INFO requests within compound SMB requests. An attacker could exploit this vulnerability by sending a specially crafted SMB request to a vulnerable ksmbd server. Successful exploitation could lead to arbitrary code execution in the context of the kernel or a denial-of-service condition. As a…
