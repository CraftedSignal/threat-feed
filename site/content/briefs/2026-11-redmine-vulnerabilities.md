---
brief_id: brief-2026-11-02-redmine-vulnerabilities
event_id: brief-2026-11-02-redmine-vulnerabilities
revision: 1
activity_at: "2026-11-02T15:34:25Z"
title: 'Redmine: Multiple security vulnerabilities'
slug: 2026-11-redmine-vulnerabilities
description: Multiple vulnerabilities in Redmine allow remote attackers to perform cross-site scripting (XSS), bypass security policies, or trigger denial-of-service conditions.
date: "2026-11-02T15:34:25Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Verified vendor advisory details against source
tags:
  - vulnerability
  - webserver
  - patch-management
vendors:
  - Redmine
products:
  - Redmine (< 6.0.12, 6.1.x < 6.1.6, 7.0.x < 7.0.3)
references:
  - https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1434/
  - https://www.redmine.org/projects/redmine/wiki/security_advisories
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  mitigation_plan:
    - priority: immediate
      action: Upgrade Redmine to version 6.0.12, 6.1.6, or 7.0.3
      owner: IT Operations
      addresses: Multiple Redmine vulnerabilities
      evidence: Source documentation references the Redmine security_advisories dated 02 November 2026
---

Multiple vulnerabilities have been identified in Redmine that may permit remote exploitation. These issues include cross-site scripting (XSS), security policy bypasses, and denial-of-service (DoS) conditions. The CERT-FR advisory references security patches issued by the Redmine project on November 2, 2026.

## Recommendation

- Upgrade Redmine to version 6.0.12, 6.1.6, 7.0.3, or later as specified in the official Redmine security advisories.
- Review the Redmine security advisories page for specific patching instructions and version compatibility.
