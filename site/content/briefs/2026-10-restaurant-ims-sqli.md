---
brief_id: brief-2026-10-25-restaurant-ims-sqli
event_id: brief-2026-10-25-restaurant-ims-sqli
revision: 1
activity_at: "2026-10-25T04:25:44Z"
title: 'Restaurant_IMS: SQL injection in lsmodal.php (CVE-2026-115999)'
slug: 2026-10-restaurant-ims-sqli
description: A SQL injection vulnerability exists in the Restaurant_IMS application, where manipulation of the login_id or epsw arguments in the lsmodal.php file leads to SQL injection.
date: "2026-10-25T04:25:44Z"
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
  - cpe:2.3:a:mansi_k:restaurant_ims:*:*:*:*:*:*:*:*
vendors:
  - mansi-k
products:
  - Restaurant_IMS (commit d7ad49f61ab7cc1ec6eb359ac2b5378bdbde0694)
cves:
  - id: CVE-2026-115999
    cvss: 7.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115999
---

A vulnerability has been found in mansi-k Restaurant_IMS commit d7ad49f61ab7cc1ec6eb359ac2b5378bdbde0694. The function `mysqli_connect` in `lsmodal.php` is affected. Manipulation of the `login_id` or `epsw` arguments allows for SQL injection. Remote exploitation is possible. The vendor was contacted but did not respond. No version details are provided due to the project's rolling release approach.
