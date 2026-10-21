---
brief_id: brief-2026-10-21-django-rest-token-revocation
event_id: brief-2026-10-21-django-rest-token-revocation
revision: 1
activity_at: "2026-10-21T21:41:23Z"
title: 'Django REST framework: Token revocation failure (CVE-2026-114137)'
slug: 2026-10-django-rest-token-revocation
description: Django REST framework versions 3.12.0 through 3.18.1 contain a logic flaw where TokenProxy.delete() uses an incorrect primary key, causing credential revocation attempts to fail silently.
date: "2026-10-21T21:41:23Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Verified against CVE-2026-114137 metadata
cpes:
  - cpe:2.3:a:django_rest_framework:django_rest_framework:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - web-api
  - django
vendors:
  - Django REST framework
products:
  - Django REST framework (3.12.0 - 3.18.1)
cves:
  - id: CVE-2026-114137
    cvss: 7.4
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-114137
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade Django REST framework to version 3.18.2
      owner: IT Operations
      due: 48h
      evidence: This issue is fixed in version 3.18.2.
  enrichment_needed:
    - item: Application audit of token revocation logic
      owner: Detection Engineering
      reason: Identify if the application uses the vulnerable TokenProxy.delete() method in custom code
      evidence: Applications, administrative integrations, or operational scripts that revoke credentials through a TokenProxy instance can therefore believe revocation succeeded while the token remains live
---

Django REST framework versions 3.12.0 to 3.18.1 contain a logic vulnerability in the `TokenProxy.delete()` method within `rest_framework/authtoken/models.py`. The method incorrectly uses the user ID primary key instead of the token string primary key when executing database deletion queries. As a result, the query fails to locate the target record and reports zero deletions without triggering an error or exception.

Any application, administrative integration, or operational script relying on this method to revoke access will incorrectly process the operation as successful. Because Django REST framework tokens do not expire automatically, this vulnerability allows revoked or compromised tokens to remain active indefinitely, granting continued unauthorized access to APIs. This issue is fixed in version 3.18.2.

## Impact
Attackers can maintain persistent access to APIs despite administrator attempts to revoke their credentials. The silent failure prevents security monitoring tools or automated lifecycle management scripts from detecting that the token remains valid in the database.

## Recommendation
- Upgrade Django REST framework to version 3.18.2 or later immediately.
- Audit custom scripts, management commands, and administrative API integrations that perform token revocation to ensure they do not rely on `TokenProxy.delete()`.
- For affected systems, perform a database audit to identify orphaned or unintended active tokens that were mistakenly thought to be deleted by automated processes.
- Transition to using explicit record deletion methods, such as `Token.objects.filter(key=...).delete()`, which correctly target the token string primary key.
