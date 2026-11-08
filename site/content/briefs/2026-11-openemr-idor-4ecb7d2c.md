---
brief_id: brief-2026-11-08-openemr-idor-4ecb7d2c
event_id: brief-2026-11-08-openemr-idor-4ecb7d2c
revision: 1
activity_at: "2026-11-08T19:33:41Z"
title: 'OpenEMR: Insecure direct object reference in portal/lib/persist.php (CVE-2026-124453)'
slug: 2026-11-openemr-idor-4ecb7d2c
description: OpenEMR versions before 8.3.0 contain an insecure direct object reference vulnerability in portal/lib/persist.php that allows authenticated portal patients to write settings for other patients.
date: "2026-11-08T19:33:41Z"
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
products:
  - OpenEMR (< 8.3.0)
cves:
  - id: CVE-2026-124453
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-124453
---

OpenEMR before 8.3.0 contains an insecure direct object reference vulnerability in portal/lib/persist.php. Authenticated portal patients can modify the setting_patient parameter in a JSON POST request to another patient's PID, allowing them to alter that patient's portal settings, such as the portal theme.
