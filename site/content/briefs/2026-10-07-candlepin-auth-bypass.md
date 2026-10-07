---
title: Authorization Bypass Vulnerability in Candlepin
slug: 2026-10-07-candlepin-auth-bypass
description: A flaw in the Candlepin authorization filter allows low-privileged authenticated users to bypass security checks and access unauthorized resources by exploiting flawed parameter verification.
date: "2026-10-07T08:35:46Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:redhat:candlepin:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - authentication-bypass
  - privilege-escalation
vendors:
  - Red Hat
products:
  - Candlepin
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A low-privilege authenticated attacker who can access the first referenced object can bypass authorization checks on subsequent objects.
    confidence_band: high
cves:
  - id: CVE-2026-106471
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-106471
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Patch all instances of Candlepin with the version provided by Red Hat.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-106471
  hunt_leads:
    - lead: Identify multiple 403 Forbidden errors followed by successful requests to sensitive subscription resource endpoints from low-privilege accounts.
      technique_id: T1068
      data_needed:
        - Web server access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Authorization filter failure enables access to unauthorized objects.
---

A vulnerability identified as CVE-2026-106471 exists within the Candlepin authorization framework. The issue stems from the central authorization filter failing to correctly implement logic for '@Verify-annotated' parameters. Instead of enforcing that all required entities associated with a request are verified, the filter grants access if at least one parameter is accessible. This allows a low-privilege authenticated attacker to bypass authorization checks on subsequent objects. By identifying target resource identifiers, an attacker can access sensitive consumer information and potentially modify entitlements and subscription resources across different organizational boundaries. This vulnerability poses a significant risk to the integrity and confidentiality of subscription management data.

## Impact

The vulnerability enables unauthorized information disclosure and unauthorized modification of subscription resources. Successful exploitation allows low-privileged users to perform actions outside their permitted scope, potentially affecting resources across organizations, which could lead to significant data breaches and administrative misconfiguration of subscription environments.

## Recommendation

Prioritize applying the vendor-supplied security patches for Candlepin to resolve the flawed authorization filter logic. Monitor system access logs for anomalous, high-frequency requests targeting sensitive resource identifiers that typically require elevated privileges.
