---
brief_id: brief-2026-11-23-laravel-dos
event_id: brief-2026-11-23-laravel-dos
revision: 1
activity_at: "2026-11-23T16:49:41Z"
title: 'Laravel: Remote denial of service vulnerability'
slug: 2026-11-laravel-dos
description: A vulnerability in the Laravel framework allows a remote attacker to cause a denial of service (DoS) in affected versions of the 12.x and 13.x branches.
date: "2026-11-23T16:49:41Z"
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
  validation_status: Checked against CERT-FR advisory and vendor security advisory.
tags:
  - denial-of-service
  - web-application
  - vulnerability
vendors:
  - Laravel
products:
  - laravel/framework (versions 12.x prior to 12.74.0)
  - laravel/framework (versions 13.x prior to 13.38.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Une vulnérabilité a été découverte dans Laravel. Elle permet à un attaquant de provoquer un déni de service à distance.
    confidence_band: high
references:
  - https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1601/
  - https://github.com/laravel/framework/security/advisories/GHSA-8h64-cpq2-9h2g
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade laravel/framework to 12.74.0 or 13.38.0 based on current branch usage.
      owner: IT Operations
      due: 48h
      evidence: Vendor security advisory GHSA-8h64-cpq2-9h2g
  hunt_leads:
    - lead: Identify spikes in HTTP 500 error codes or sudden process crashes specifically targeting Laravel application endpoints, potentially indicating exploitation attempts for the disclosed remote denial of service vulnerability.
      technique_id: T1499
      data_needed:
        - Web server access logs
        - Application error logs
        - System performance monitoring metrics
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Une vulnérabilité a été découverte dans Laravel. Elle permet à un attaquant de provoquer un déni de service à distance.
  mitigation_plan:
    - priority: immediate
      action: Patch Laravel to version 12.74.0 or 13.38.0
      owner: IT Operations
      addresses: Laravel framework remote DoS
      evidence: Vendor advisory GHSA-8h64-cpq2-9h2g
---

## Overview

A remote denial of service (DoS) vulnerability has been identified in the Laravel framework, specifically affecting versions 12.x before 12.74.0 and 13.x before 13.38.0. The vulnerability is tracked under GitHub Advisory GHSA-8h64-cpq2-9h2g. Detailed exploitation mechanics remain undisclosed in the public advisory, requiring users to rely on the vendor's patch documentation.

## Impact

Successful exploitation of this vulnerability results in a remote denial of service, rendering the affected Laravel application unavailable to legitimate users.

## Recommendation

Administrators must update their Laravel framework installations immediately to the patched versions: 12.74.0 or higher for the 12.x branch, and 13.38.0 or higher for the 13.x branch. Review the official Laravel security advisory at https://github.com/laravel/framework/security/advisories/GHSA-8h64-cpq2-9h2g for specific patch instructions and dependencies.
