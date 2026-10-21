---
brief_id: brief-2026-10-21-insurance-management-sql-injection
event_id: brief-2026-10-21-insurance-management-sql-injection
revision: 1
activity_at: "2026-10-21T13:18:46Z"
title: 'Insurance-Management-System: SQL injection in editPlan.php (CVE-2026-114242)'
slug: 2026-10-insurance-management-sql-injection
description: A SQL injection vulnerability exists in the Insurance-Management-System project due to manipulation of the Plan_no/Name argument in /Admin/View/editPlan.php.
date: "2026-10-21T13:18:46Z"
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
  - Insurance-Management-System (rolling release)
cves:
  - id: CVE-2026-114242
    cvss: 7.3
    kev_status: "false"
references:
  - CVE-2026-114242
  - https://nvd.nist.gov/vuln/detail/CVE-2026-114242
---

A vulnerability was identified in dhikshitha29 Insurance-Management-System (commit 91de5edda5baa109ad8e9baf03ce6a3ceda84183/125362cc21dca20d74091a4913a5096bb58dd837). The function `mysqli_query` in `/Admin/View/editPlan.php` is susceptible to SQL injection via the `Plan_no` or `Name` argument. The attack can be executed remotely, and a public exploit is available. The project uses a rolling release model, and no fix has been provided by the maintainer.
