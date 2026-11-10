---
brief_id: brief-2026-11-10-dns-kerberos-coercion
event_id: brief-2026-11-10-dns-kerberos-coercion
revision: 1
activity_at: "2026-11-10T02:45:15Z"
title: Kerberos Coercion via DNS Object SPN Spoofing
slug: 2026-11-dns-kerberos-coercion
description: Adversaries manipulate DNS records to spoof Service Principal Names (SPNs) and inject marshaled CREDENTIAL_TARGET_INFORMATION structures into DNS queries to coerce authentication from victim systems to attacker-controlled hosts.
date: "2026-11-10T02:45:15Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
cpes:
  - cpe:2.3:o:microsoft:windows_10_1507:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10_1607:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10_1809:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10_21h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10_22h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_11_22h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_11_23h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_11_24h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2008:-:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2008:r2:sp1:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_server_2012:-:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2012:r2:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2016:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2019:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2022_23h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2025:*:*:*:*:*:*:*:*
tags:
  - dns-spoofing
  - kerberos
  - credential-access
  - windows
  - coercion
cves:
  - id: CVE-2025-33073
    cvss: 8.8
    epss: 0.82829
    kev_status: "false"
references:
  - https://www.synacktiv.com/en/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025
  - https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/dns_query/dns_query_win_kerberos_coercion_via_dns_object_spoofing.yml
---

Attackers perform Kerberos coercion by manipulating DNS objects to spoof Service Principal Names (SPNs). This technique involves the use of DNS queries containing the pattern "1UWhRCAAAAA..BAAAA," which corresponds to a base64-encoded marshaled CREDENTIAL_TARGET_INFORMATION structure. This activity is associated with Kerberos coercion attacks, including those related to CVE-2025-33073.
