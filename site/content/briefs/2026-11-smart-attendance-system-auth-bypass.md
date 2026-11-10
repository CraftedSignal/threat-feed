---
brief_id: brief-2026-11-10-smart-attendance-system-auth-bypass
event_id: brief-2026-11-10-smart-attendance-system-auth-bypass
revision: 1
activity_at: "2026-11-10T12:15:42Z"
title: 'SourceCodester Smart Attendance System: Authentication vulnerability (CVE-2026-125075)'
slug: 2026-11-smart-attendance-system-auth-bypass
description: A vulnerability in SourceCodester Smart Attendance System with QR Code Scanner 1.0 allows for missing authentication via manipulation of the e argument in create_admin.php.
date: "2026-11-10T12:15:42Z"
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
  - cpe:2.3:a:sourcecodester:smart_attendance_system_with_qr_code_scanner:*:*:*:*:*:*:*:*
vendors:
  - SourceCodester
products:
  - Smart Attendance System with QR Code Scanner (1.0)
cves:
  - id: CVE-2026-125075
    cvss: 7.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-125075
---

A vulnerability has been identified in SourceCodester Smart Attendance System with QR Code Scanner 1.0. The issue affects the getMessage function in create_admin.php within the Admin Account Creation component. Manipulation of the argument 'e' leads to missing authentication. The attack can be performed remotely, and public exploit code exists.
