---
brief_id: brief-2026-10-30-pybars4-code-injection
event_id: brief-2026-10-30-pybars4-code-injection
revision: 1
activity_at: "2026-10-30T17:37:21Z"
title: 'pybars4: Code injection in pybars/_compiler.py (CVE-2026-119717)'
slug: 2026-10-pybars4-code-injection
description: The pybars4 library through 0.9.13 contains a code injection vulnerability in pybars/_compiler.py that allows execution of Python code via unescaped bracketed path segments in Handlebars templates.
date: "2026-10-30T17:37:21Z"
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
  - pybars4 (<= 0.9.13)
cves:
  - id: CVE-2026-119717
    cvss: 8.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119717
---

CVE-2026-119717 identifies a code injection vulnerability in pybars4 through 0.9.13. The flaw exists in 'pybars/_compiler.py'. Attackers can supply a template with a crafted segment in a helper or block argument to break out of the generated 'resolve()' string literal and execute Python code in the application process.
