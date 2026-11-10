---
brief_id: brief-2026-11-10-smart-attendance-password-reset
event_id: brief-2026-11-10-smart-attendance-password-reset
revision: 1
activity_at: "2026-11-10T04:02:22Z"
title: 'SourceCodester Smart Attendance System: Password reset manipulation (CVE-2026-125074)'
slug: 2026-11-smart-attendance-password-reset
description: A flaw in the SourceCodester Smart Attendance System with QR Code Scanner 1.0 allows remote manipulation of username/password arguments during password recovery, resulting in weak password recovery.
date: "2026-11-10T04:02:22Z"
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
  - cpe:2.3:a:sourcecodester:smart_attendance_system_with_qr_code_scanner:1.0:*:*:*:*:*:*:*
vendors:
  - SourceCodester
products:
  - Smart Attendance System with QR Code Scanner (1.0)
cves:
  - id: CVE-2026-125074
    cvss: 7.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-125074
---

A vulnerability exists in the `reset_password.php` file of the SourceCodester Smart Attendance System with QR Code Scanner 1.0. The flaw allows for the remote manipulation of username or password arguments within the password recovery component, leading to weak password recovery. An exploit for this vulnerability has been published.
