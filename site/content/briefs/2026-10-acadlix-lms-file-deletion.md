---
brief_id: brief-2026-10-31-acadlix-lms-file-deletion
event_id: brief-2026-10-31-acadlix-lms-file-deletion
revision: 1
activity_at: "2026-10-31T13:55:16Z"
title: 'Acadlix LMS: Arbitrary file deletion (CVE-2026-103882)'
slug: 2026-10-acadlix-lms-file-deletion
description: The Acadlix LMS plugin for WordPress is vulnerable to arbitrary file deletion in the post_delete_assessment_file_by_id function due to insufficient file path validation and an improper permission callback, allowing unauthenticated attackers to delete files on the server.
date: "2026-10-31T13:55:16Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
tags:
  - wordpress
  - arbitrary-file-deletion
  - rce
products:
  - Acadlix LMS – AI Quiz Maker, Online Exam & Course Plugin (<= 1.1.9)
cves:
  - id: CVE-2026-103882
    cvss: 9.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-103882
---

The Acadlix LMS - AI Quiz Maker, Online Exam & Course Plugin for WordPress (all versions up to and including 1.1.9) contains an arbitrary file deletion vulnerability in the post_delete_assessment_file_by_id function. The plugin's REST API permission callback only verifies a generic wp_rest nonce emitted in the public acadlixOptions JavaScript object, which effectively allows unauthenticated access. This vulnerability may lead to remote code execution by deleting critical files such as wp-config.php.
