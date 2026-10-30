---
brief_id: brief-2026-10-30-django-sql-injection
event_id: brief-2026-10-30-django-sql-injection
revision: 1
activity_at: "2026-10-30T21:03:27Z"
title: 'Django: SQL injection in FilteredRelation (CVE-2025-57833)'
slug: 2026-10-django-sql-injection
description: A SQL injection vulnerability in Django allows unauthenticated attackers to execute arbitrary SQL commands via insufficiently validated column aliases in FilteredRelation features.
date: "2026-10-30T21:03:27Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Ready for deployment
cpes:
  - cpe:2.3:a:djangoproject:django:*:*:*:*:*:*:*:*
tags:
  - web-application
  - sql-injection
  - cve
vendors:
  - Django
products:
  - Django (4.2 < 4.2.24)
  - Django (5.1 < 5.1.12)
  - Django (5.2 < 5.2.6)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A SQL injection vulnerability in Django that emerged after about a year, at first glance it appears to be caused by an alias (since aliases cannot be precompiled).
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server Software Component
    evidence: The SQL statement successfully compiled at the bottom layer is... select user
    confidence_band: high
cves:
  - id: CVE-2025-57833
    cvss: 7.1
    epss: 0.26106
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-57833
  - https://docs.djangoproject.com/en/dev/releases/security
  - https://xz.aliyun.com/news/19236
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-SW0RD1IGHT-CVE-2025-57833&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch Django to 4.2.24 or later
      owner: IT Operations
      due: 48h
      evidence: Django security release documentation
  hunt_leads:
    - lead: Identify HTTP POST requests to application endpoints that contain unusual or semicolon-terminated strings in JSON parameters mapped to query aliases
      technique_id: T1190
      data_needed:
        - Web server logs (access logs)
        - Application request payload logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: 'Exploitation example: {"alias":" using(id);select user --","author":"Bob"}'
  mitigation_plan:
    - priority: immediate
      action: Upgrade Django to 4.2.24, 5.1.12, or 5.2.6
      owner: IT Operations
      addresses: CVE-2025-57833
      evidence: Vendor security advisory
---

CVE-2025-57833 is a SQL injection vulnerability within the Django framework. The vulnerability exists in the FilteredRelation feature, specifically when using QuerySet.annotate() or QuerySet.alias() methods. Insufficient validation of dictionary keys (column aliases) provided via Python's dictionary expansion allows an attacker to inject arbitrary SQL statements into the database query.

## Impact

Successful exploitation allows an attacker to execute arbitrary SQL queries against the backend database. This could result in unauthorized data access, modification, or potential privilege escalation within the database environment, depending on the permissions of the database user.

## Recommendation

* Update Django to versions 4.2.24, 5.1.12, 5.2.6, or later to address the insufficient alias validation.
* Audit applications for usage of dynamic inputs as dictionary keys within annotate() or alias() methods.
* Implement strict input validation for any user-supplied data used in ORM aliases.
* Restrict database user permissions to follow the principle of least privilege.
