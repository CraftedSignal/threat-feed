---
brief_id: brief-2026-11-23-roundcube-vulnerabilities-11120df6
event_id: brief-2026-11-23-roundcube-vulnerabilities-11120df6
revision: 1
activity_at: "2026-11-23T16:49:31Z"
title: Roundcube Webmail Multiple Vulnerabilities
slug: 2026-11-roundcube-vulnerabilities-11120df6
description: Roundcube Webmail versions 1.6.x before 1.6.22 and 1.7.x before 1.7.7 contain multiple vulnerabilities enabling remote code execution, remote denial of service, and unauthorized data access.
date: "2026-11-23T16:49:31Z"
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
  verdict: pass_with_fixes
  validation_status: Upstream vendor documentation is confirmed. Environment inventory validation is pending.
vendors:
  - Roundcube
products:
  - Roundcube Webmail (1.6.x < 1.6.22)
  - Roundcube Webmail (1.7.x < 1.7.7)
references:
  - https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1602/
  - https://roundcube.net/news/2026/11/23/security-updates-1.6.22-and-1.7.7
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory all internal Roundcube Webmail deployments and assess against fixed versions 1.6.22 and 1.7.7.
      owner: IT Operations
      due: 24h
      evidence: Vendor security updates 1.6.22 and 1.7.7 address disclosed vulnerabilities.
  mitigation_plan:
    - priority: immediate
      action: Upgrade affected Roundcube Webmail installations to version 1.6.22 or 1.7.7.
      owner: IT Operations
      addresses: Multiple vulnerabilities in Roundcube Webmail
      evidence: https://roundcube.net/news/2026/11/23/security-updates-1.6.22-and-1.7.7
---

## Overview
Multiple vulnerabilities have been identified in Roundcube Webmail, allowing attackers to achieve remote code execution, remote denial of service, and breaches of data confidentiality. The vulnerabilities affect the 1.6.x branch for versions prior to 1.6.22 and the 1.7.x branch for versions prior to 1.7.7. The vendor has released security updates 1.6.22 and 1.7.7 to address these issues.

## Recommendation
Upgrade all instances of Roundcube Webmail to the fixed versions 1.6.22 or 1.7.7 immediately to mitigate identified risks. Refer to the official Roundcube security update release for detailed installation instructions.
