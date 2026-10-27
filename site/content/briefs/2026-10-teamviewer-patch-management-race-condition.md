---
brief_id: brief-2026-10-27-teamviewer-patch-management-race-condition
event_id: brief-2026-10-27-teamviewer-patch-management-race-condition
revision: 1
activity_at: "2026-10-27T20:01:11Z"
title: 'TeamViewer Remote Management: Local privilege escalation via race condition (CVE-2026-111584)'
slug: 2026-10-teamviewer-patch-management-race-condition
description: A race condition in TeamViewer Remote Management - Patch Management for Windows allows low-privileged local authenticated attackers to execute arbitrary code with elevated privileges.
date: "2026-10-27T20:01:11Z"
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
  - cpe:2.3:a:teamviewer:remote_management_patch_management:*:*:*:*:*:*:*:*
vendors:
  - TeamViewer
products:
  - TeamViewer Remote Management - Patch Management (< 26.9.1)
affected_os:
  - Windows
cves:
  - id: CVE-2026-111584
    cvss: 7.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111584
---

CVE-2026-111584 describes a race condition in the installation process of TeamViewer Remote Management - Patch Management for Windows prior to version 26.9.1. An authenticated local attacker with low privileges can exploit this by replacing the service executable in an insufficiently protected temporary directory during Patch Management activation, resulting in arbitrary code execution with elevated privileges.
