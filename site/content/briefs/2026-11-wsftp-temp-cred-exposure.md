---
brief_id: brief-2026-11-09-wsftp-temp-cred-exposure
event_id: brief-2026-11-09-wsftp-temp-cred-exposure
revision: 1
activity_at: "2026-11-09T17:50:28Z"
title: 'Progress Software WS_FTP Server: Sensitive credential and session data exposure (CVE-2026-115340)'
slug: 2026-11-wsftp-temp-cred-exposure
description: Progress Software WS_FTP Server versions prior to 2025.0.5 on Windows may write sensitive user credential and session data to a temporary file during file transfer operations.
date: "2026-11-09T17:50:28Z"
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
  - cpe:2.3:a:progress_software:ws_ftp_server:*:*:*:*:*:*:*:*
vendors:
  - Progress Software
products:
  - WS_FTP Server (< 2025.0.5)
affected_os:
  - Windows
cves:
  - id: CVE-2026-115340
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115340
---

Progress Software WS_FTP Server versions prior to 2025.0.5 on Windows may write sensitive user credential and session data to a temporary file during file transfer operations.
