---
brief_id: brief-2026-11-08-openemr-sql-injection
event_id: brief-2026-11-08-openemr-sql-injection
revision: 1
activity_at: "2026-11-08T15:31:22Z"
title: 'OpenEMR: SQL injection via mass assignment in patient portal (CVE-2026-124444)'
slug: 2026-11-openemr-sql-injection
description: OpenEMR versions before 8.4.0 contain a mass assignment vulnerability in the patient portal OnsiteDocument query API that facilitates SQL injection.
date: "2026-11-08T15:31:22Z"
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
  - OpenEMR (< 8.4.0)
cves:
  - id: CVE-2026-124444
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-124444
---

OpenEMR before 8.4.0 contains a mass assignment vulnerability in the patient portal OnsiteDocument query API. The flaw allows request parameters to set bitwise criteria filters that are placed unquoted into the SQL WHERE clause. Authenticated patient portal users can exploit this to perform SQL injection and read any database table, including other patients' records and staff password hashes.
