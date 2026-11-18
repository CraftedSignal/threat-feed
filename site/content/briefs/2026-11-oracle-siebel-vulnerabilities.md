---
brief_id: brief-2026-11-18-oracle-siebel-vulnerabilities
event_id: brief-2026-11-18-oracle-siebel-vulnerabilities
revision: 1
activity_at: "2026-11-18T09:18:15Z"
title: 'Oracle Siebel CRM: Multiple Vulnerabilities'
slug: 2026-11-oracle-siebel-vulnerabilities
description: The BSI has reported multiple vulnerabilities in Oracle Siebel CRM that allow remote, anonymous, or authenticated attackers to compromise system confidentiality, integrity, and availability.
date: "2026-11-18T09:18:15Z"
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
qa_status:
  verdict: pass
vendors:
  - Oracle
products:
  - Siebel CRM
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4629
action_plan:
  priority: elevated
  mitigation_plan:
    - priority: short_term
      action: Monitor official Oracle security advisories for patches addressing the reported vulnerabilities in Siebel CRM.
      addresses: Multiple vulnerabilities in Oracle Siebel CRM
      evidence: Source identifies multiple vulnerabilities without specific CVEs or versioning.
---

## Overview
The BSI has issued an advisory regarding multiple vulnerabilities in Oracle Siebel CRM. These vulnerabilities can be exploited by remote attackers, including anonymous or authenticated users.

## Impact
Successful exploitation may impact the confidentiality, integrity, and availability of the affected Oracle Siebel CRM deployment.

## Recommendation
Administrators should monitor official security channels from Oracle for specific updates and guidance regarding these vulnerabilities as provided in the referenced advisory.
