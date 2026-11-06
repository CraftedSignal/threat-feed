---
brief_id: brief-2026-11-06-python-fips-regression
event_id: brief-2026-11-06-python-fips-regression
revision: 1
activity_at: "2026-11-06T23:27:33Z"
title: 'Python: CPython FIPS enforcement regression (CVE-2026-119170)'
slug: 2026-11-python-fips-regression
description: A high-severity regression in CPython 3.14.10 fails to enforce mandatory FIPS-compliant hash algorithm restrictions, allowing the use of prohibited algorithms in sensitive environments.
date: "2026-11-06T23:27:33Z"
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
  validation_status: Environment validation needed for FIPS audit logs
cpes:
  - cpe:2.3:a:python:python:3.14.10:*:*:*:*:*:*:*
tags:
  - vulnerability
  - fips
  - compliance
vendors:
  - Python
products:
  - CPython (3.14.10)
cves:
  - id: CVE-2026-119170
    kev_status: "false"
references:
  - https://seclists.org/oss-sec/2026/q4/564
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Compliance
  immediate_actions:
    - action: Identify and upgrade all CPython 3.14.10 installations
      owner: IT Operations
      due: 48h
      evidence: Vulnerability affects exclusively Python 3.14.10
  hunt_leads:
    - lead: Identify systems utilizing CPython 3.14.10 in FIPS-enabled environments
      data_needed:
        - Software inventory management data
        - Operating system environment variables (OPENSSL_FIPS)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Regression specifically targets FIPS enforcement logic in 3.14.10
  mitigation_plan:
    - priority: immediate
      action: Upgrade to non-vulnerable Python version
      owner: IT Operations
      addresses: CVE-2026-119170
      evidence: CPython 3.14.10 is the only affected version
---

CPython version 3.14.10 contains a regression that prevents the correct enforcement of FIPS-compliant hash algorithm restrictions. This vulnerability may result in the use of non-FIPS compliant algorithms in environments where such security policies are strictly required. The vulnerability is confirmed to affect only version 3.14.10.

## Impact

Organizations operating in environments requiring strict FIPS compliance may inadvertently utilize prohibited hashing algorithms, potentially violating regulatory or security mandates.

## Recommendation

- Upgrade all instances of CPython 3.14.10 to the next available secure version released by the Python Software Foundation.
- Audit environments where FIPS mode is enabled and CPython 3.14.10 is deployed to identify potential unauthorized use of legacy hash algorithms.
