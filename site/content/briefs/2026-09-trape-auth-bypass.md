---
title: Authorization Bypass Vulnerability in jofpin trape
slug: 2026-09-trape-auth-bypass
description: An authorization bypass vulnerability in jofpin trape 2.0, triggered by manipulating the vId or id arguments, allows remote attackers to gain unauthorized access.
date: "2026-09-04T19:27:32Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:jofpin:trape:2.0:*:*:*:*:*:*:*
tags:
  - vulnerability
  - web-application
  - access-control
vendors:
  - jofpin
products:
  - trape (2.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: The trape tool is designed for tracking and reconnaissance, and the vulnerability enables unauthorized access to this data.
    confidence_band: high
cves:
  - id: CVE-2026-85638
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85638
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Restrict network access to trape instances
      owner: SOC
      due: 24h
      evidence: Exploit is public
  mitigation_plan:
    - priority: immediate
      action: Isolate affected trape 2.0 instances
      owner: IT Operations
      addresses: CVE-2026-85638
      evidence: No vendor patch available
---

A security weakness has been identified in jofpin trape version 2.0, specifically within the core/user.py file. This vulnerability enables an authorization bypass through the manipulation of the 'vId' or 'id' arguments during user sessions. The flaw allows remote attackers to interact with the application without proper authentication, potentially leading to unauthorized data access or administrative control. An exploit for this vulnerability is currently publicly available, increasing the risk of exploitation. The vendor has been notified of the issue but has not yet provided a resolution or patch. Defenders should note that trape is often used for security research and tracking, making this an attractive target for unauthorized access.

## Impact

Successful exploitation of CVE-2026-85638 allows unauthenticated remote attackers to bypass authorization mechanisms within the trape tool. This could allow attackers to monitor, manage, or exfiltrate sensitive data collected by the tool. Given the nature of the application as a tracking and security tool, compromise could lead to the exposure of collected user metadata or the manipulation of tracking campaigns.

## Recommendation

- Restrict access to the trape interface using network-level controls (e.g., VPN, firewall rules) until a vendor patch is released.
- Implement monitoring for requests targeting the application that include manipulated 'vId' or 'id' query parameters.
- Monitor web server access logs for any anomalous patterns originating from unauthenticated sessions that attempt to access restricted functionality within core/user.py logic.
